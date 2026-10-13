/**
 * Snowflake Grant Sync
 *
 * Syncs SGNL access decisions to Snowflake by writing or deleting rows in the
 * sgnl_access_grants table via the Snowflake SQL API.
 */

class RetryableError extends Error {
  constructor(message) {
    super(message);
    this.retryable = true;
  }
}

class FatalError extends Error {
  constructor(message) {
    super(message);
    this.retryable = false;
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

// context.environment for non-secret config, context.secrets for credentials
// — mirrors the shape used by @sgnl-actions/utils getBaseURL / getAuthorizationHeader
function getBaseURL(params, context) {
  const address = params.address || (context.environment && context.environment.ADDRESS) || '';
  if (!address) {
    throw new FatalError('address is required — set params.address or configure ADDRESS in the action environment');
  }
  return address.replace(/\/$/, '');
}

// Valid token type values from Snowflake SQL API auth docs
const VALID_TOKEN_TYPES = new Set([
  'KEYPAIR_JWT',
  'OAUTH',
  'PROGRAMMATIC_ACCESS_TOKEN',
  'WORKLOAD_IDENTITY_FEDERATION',
]);

function getTokenType(params, context) {
  const secrets = context.secrets || {};

  const override = params.snowflake_auth_token_type;
  if (override) {
    if (override === 'AUTO') return null;
    if (!VALID_TOKEN_TYPES.has(override)) {
      throw new FatalError(`Invalid snowflake_auth_token_type "${override}". Valid: ${[...VALID_TOKEN_TYPES].join(', ')}, AUTO`);
    }
    return override;
  }

  if (secrets.BEARER_AUTH_TOKEN) return 'KEYPAIR_JWT';
  if (secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET || secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN) return 'OAUTH';
  return null;
}

async function getAuthorizationHeader(context) {
  const secrets = context.secrets || {};
  const environment = context.environment || {};

  if (secrets.BEARER_AUTH_TOKEN) {
    return `Bearer ${secrets.BEARER_AUTH_TOKEN}`;
  }

  if (secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN) {
    return `Bearer ${secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN}`;
  }

  if (secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET) {
    const tokenUrl = environment.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL;
    const clientId = environment.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID;
    const clientSecret = secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET;
    const scope = environment.OAUTH2_CLIENT_CREDENTIALS_SCOPE || '';
    const audience = environment.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE || '';
    const authStyle = environment.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE || '';

    if (!tokenUrl || !clientId) {
      throw new FatalError('OAuth2 client credentials require OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL and OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID');
    }

    console.log(`OAuth2 token request: url=${tokenUrl} clientId=${clientId} scope=${scope} authStyle=${authStyle || 'InHeader'}`);

    const params = new URLSearchParams();
    params.append('grant_type', 'client_credentials');
    if (scope) params.append('scope', scope);
    if (audience) params.append('audience', audience);

    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
    };

    if (authStyle === 'InParams') {
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
    } else {
      headers['Authorization'] = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    }

    console.log(`OAuth2 token request body: ${params.toString()}`);

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers,
      body: params.toString(),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`OAuth2 token response status=${response.status} body=${text}`);
      throw new FatalError(`OAuth2 token fetch failed ${response.status}: ${text}`);
    }

    const data = await response.json();
    return `Bearer ${data.access_token}`;
  }

  throw new FatalError('No authentication credentials found. Configure BEARER_AUTH_TOKEN, OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN, or OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET.');
}

async function executeStatement(address, sql, authHeader, tokenType) {
  const headers = {
    'Authorization': authHeader,
    'Content-Type': 'application/json',
    'Accept': '*/*',
  };

  if (tokenType) {
    headers['X-Snowflake-Authorization-Token-Type'] = tokenType;
  }

  const response = await fetch(`${address}/api/v2/statements`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ statement: sql, timeout: 30 }),
  });

  if (!response.ok) {
    const body = await response.text();
    if (response.status === 429) throw new RetryableError('Snowflake SQL API rate limit exceeded');
    if (response.status === 401) throw new FatalError('Invalid or expired authentication token');
    if (response.status === 403) throw new FatalError('Insufficient permissions to execute statement');
    if (response.status === 422) throw new FatalError(`Invalid SQL statement: ${body}`);
    if (response.status >= 500) throw new RetryableError(`Snowflake API server error ${response.status}`);
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
    console.log('Starting Snowflake Grant Sync action');

    validateInputs(params);

    const snowflakeUser = params.snowflake_user.toUpperCase(); // current_user() returns uppercase
    const resourceType = params.resource_type || '';
    const action = params.action;

    const tokenType = getTokenType(params, context);
    const authHeader = await getAuthorizationHeader(context);
    const address = getBaseURL(params, context);

    console.log(`Executing ${action} for user ${snowflakeUser}${resourceType ? ` resource ${resourceType}` : ''}`);

    const sql = buildSql(action, snowflakeUser, resourceType);
    await executeStatement(address, sql, authHeader, tokenType);

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
    console.error(`Error handler invoked: ${error?.message}`);
    throw error;
  },

  halt: async (params, _context) => {
    const { reason } = params;
    console.log(`Job halted: ${reason}`);
    return {
      status: 'halted',
      reason: reason || 'unknown',
      halted_at: new Date().toISOString(),
    };
  },
};
