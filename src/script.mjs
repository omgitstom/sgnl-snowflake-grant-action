/**
 * Snowflake Grant Sync
 *
 * Syncs SGNL access decisions to Snowflake's sgnl_access_grants table via
 * the Snowflake SQL API. Supports grant, revoke, and full_revoke operations.
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

function getTokenType(context) {
  if (context.env.SNOWFLAKE_AUTH_TOKEN_TYPE) {
    return context.env.SNOWFLAKE_AUTH_TOKEN_TYPE;
  }
  return 'OAUTH';
}

async function executeStatement(address, sql, token, tokenType) {
  const response = await fetch(`${address}/api/v2/statements`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'X-Snowflake-Authorization-Token-Type': tokenType,
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
    const address = (params.address || 'https://uofnoea-wyc03001.snowflakecomputing.com').replace(/\/$/, '');

    const token = context.env.OAUTH_TOKEN;
    if (!token) {
      throw new FatalError('OAUTH_TOKEN environment variable is required');
    }
    const tokenType = getTokenType(context);

    console.log(`Executing ${action} for user ${snowflakeUser}${resourceType ? ` resource ${resourceType}` : ''}`);

    const sql = buildSql(action, snowflakeUser, resourceType);
    await executeStatement(address, sql, token, tokenType);

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
