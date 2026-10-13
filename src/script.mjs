/**
 * Snowflake Grant Sync
 *
 * Syncs SGNL access decisions to Snowflake by writing or deleting rows in the
 * sgnl_access_grants table via the Snowflake SQL API.
 */

class RetryableError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RetryableError';
  }
}

class FatalError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FatalError';
  }
}

function validateInputs(params) {
  if (!params.snowflake_user || typeof params.snowflake_user !== 'string' || params.snowflake_user.trim() === '') {
    throw new FatalError('snowflake_user is required and must be a non-empty string');
  }
  const validActions = ['grant', 'revoke', 'full_revoke'];
  if (!validActions.includes(params.action)) {
    throw new FatalError(`action must be one of: ${validActions.join(', ')}`);
  }
  if (params.action !== 'full_revoke' && (!params.resource_type || typeof params.resource_type !== 'string' || params.resource_type.trim() === '')) {
    throw new FatalError('resource_type is required for grant and revoke actions');
  }
}

/**
 * Resolve the base URL. Checks params.address first, then context.env.ADDRESS,
 * matching the convention of @sgnl-actions/utils getBaseURL.
 */
function getBaseURL(params, context) {
  const address = params.address || (context.env && context.env.ADDRESS) || '';
  if (!address) {
    throw new FatalError('address is required — set it as an input or via the ADDRESS environment variable');
  }
  return address.replace(/\/$/, '');
}

/**
 * Build the Authorization header value. Priority order matches @sgnl-actions/utils:
 *   1. Bearer token (BEARER_AUTH_TOKEN secret)
 *   2. OAuth2 authorization code access token
 *   3. OAuth2 client credentials (fetches a new token)
 */
async function getAuthorizationHeader(context) {
  const secrets = context.secrets || {};
  const env = context.env || {};

  if (secrets.BEARER_AUTH_TOKEN) {
    return `Bearer ${secrets.BEARER_AUTH_TOKEN}`;
  }

  if (secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN) {
    return `Bearer ${secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN}`;
  }

  if (secrets.CLIENT_ID && secrets.CLIENT_SECRET && env.TOKEN_URL) {
    const credentials = Buffer.from(`${secrets.CLIENT_ID}:${secrets.CLIENT_SECRET}`).toString('base64');
    const response = await fetch(env.TOKEN_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
    });
    if (!response.ok) {
      const body = await response.text();
      throw new FatalError(`OAuth2 token fetch failed ${response.status}: ${body}`);
    }
    const data = await response.json();
    return `Bearer ${data.access_token}`;
  }

  throw new FatalError('No authentication credentials found. Configure BEARER_AUTH_TOKEN, OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN, or OAuth2 client credentials.');
}

async function executeStatement(address, sql, authHeader) {
  const response = await fetch(`${address}/api/v2/statements`, {
    method: 'POST',
    headers: {
      'Authorization': authHeader,
      'X-Snowflake-Authorization-Token-Type': 'OAUTH',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ statement: sql, timeout: 30 }),
  });

  if (response.status === 429) {
    throw new RetryableError('Snowflake SQL API rate limit exceeded');
  }
  if (response.status === 401 || response.status === 403) {
    const body = await response.text();
    throw new FatalError(`Snowflake SQL API auth failure ${response.status}: ${body}`);
  }
  if (response.status >= 500) {
    const body = await response.text();
    throw new RetryableError(`Snowflake SQL API server error ${response.status}: ${body}`);
  }
  if (!response.ok) {
    const body = await response.text();
    throw new FatalError(`Snowflake SQL API error ${response.status}: ${body}`);
  }

  return response.json();
}

function buildSql(action, snowflakeUser, resourceType) {
  switch (action) {
    case 'grant':
      return `
        MERGE INTO sgnl_demo.sgnl_policy.sgnl_access_grants AS target
        USING (SELECT '${snowflakeUser}' AS snowflake_user, '${resourceType}' AS resource_type) AS src
        ON target.snowflake_user = src.snowflake_user AND target.resource_type = src.resource_type
        WHEN MATCHED THEN UPDATE SET granted_at = current_timestamp(), expires_at = NULL
        WHEN NOT MATCHED THEN INSERT (snowflake_user, resource_type, granted_at)
          VALUES (src.snowflake_user, src.resource_type, current_timestamp())
      `;
    case 'revoke':
      return `
        DELETE FROM sgnl_demo.sgnl_policy.sgnl_access_grants
        WHERE snowflake_user = '${snowflakeUser}'
          AND resource_type  = '${resourceType}'
      `;
    case 'full_revoke':
      return `
        DELETE FROM sgnl_demo.sgnl_policy.sgnl_access_grants
        WHERE snowflake_user = '${snowflakeUser}'
      `;
  }
}

export default {
  invoke: async (params, context) => {
    validateInputs(params);

    const snowflakeUser = params.snowflake_user.toUpperCase(); // current_user() returns uppercase
    const resourceType = params.resource_type || '';
    const action = params.action;
    const address = getBaseURL(params, context);
    const authHeader = await getAuthorizationHeader(context);

    console.log(`Executing ${action} for user ${snowflakeUser}${resourceType ? ` resource ${resourceType}` : ''}`);

    const sql = buildSql(action, snowflakeUser, resourceType);
    await executeStatement(address, sql, authHeader);

    console.log(`Successfully completed ${action} for ${snowflakeUser}`);

    return {
      status: 'ok',
      action,
      snowflake_user: snowflakeUser,
      resource_type: resourceType,
      completed_at: new Date().toISOString(),
    };
  },

  error: async (params, _context) => {
    const { error } = params;
    console.error(`Job failed: ${error.message}`);
    throw new Error(`Unable to recover: ${error.message}`);
  },

  halt: async (params, _context) => {
    const { reason } = params;
    console.log(`Job halted: ${reason}`);
    return {
      status: 'halted',
      reason,
      halted_at: new Date().toISOString(),
    };
  },
};
