import script from '../src/script.mjs';

const makeContext = (envOverrides = {}) => ({
  env: {
    OAUTH_TOKEN: 'test-token',
    ...envOverrides,
  },
  secrets: {},
  outputs: {},
});

describe('invoke', () => {
  let fetchMock;

  beforeEach(() => {
    fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ statementHandle: 'abc123' }),
    });
    global.fetch = fetchMock;
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  test('grant calls SQL API with MERGE statement', async () => {
    const result = await script.invoke(
      { snowflake_user: 'alice', resource_type: 'Engineering', action: 'grant' },
      makeContext()
    );

    expect(result.status).toBe('ok');
    expect(result.action).toBe('grant');
    expect(result.snowflake_user).toBe('ALICE');
    expect(result.resource_type).toBe('Engineering');
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toContain('/api/v2/statements');
    const body = JSON.parse(options.body);
    expect(body.statement).toMatch(/MERGE INTO/i);
    expect(body.statement).toContain('ALICE');
    expect(body.statement).toContain('Engineering');
  });

  test('revoke calls SQL API with DELETE statement scoped to resource', async () => {
    const result = await script.invoke(
      { snowflake_user: 'carol', resource_type: 'Finance', action: 'revoke' },
      makeContext()
    );

    expect(result.status).toBe('ok');
    expect(result.action).toBe('revoke');
    expect(result.snowflake_user).toBe('CAROL');

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.statement).toMatch(/DELETE FROM/i);
    expect(body.statement).toContain('CAROL');
    expect(body.statement).toContain('Finance');
  });

  test('full_revoke calls SQL API with DELETE for all user rows', async () => {
    const result = await script.invoke(
      { snowflake_user: 'bob', action: 'full_revoke' },
      makeContext()
    );

    expect(result.status).toBe('ok');
    expect(result.action).toBe('full_revoke');
    expect(result.snowflake_user).toBe('BOB');

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.statement).toMatch(/DELETE FROM/i);
    expect(body.statement).toContain('BOB');
    expect(body.statement).not.toContain('resource_type');
  });

  test('uppercases snowflake_user before sending', async () => {
    await script.invoke(
      { snowflake_user: 'Alice', resource_type: 'Engineering', action: 'grant' },
      makeContext()
    );
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.statement).toContain('ALICE');
    expect(body.statement).not.toContain("'Alice'");
  });

  test('uses custom address when provided', async () => {
    await script.invoke(
      { snowflake_user: 'alice', resource_type: 'Engineering', action: 'grant', address: 'https://custom.snowflakecomputing.com' },
      makeContext()
    );
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain('https://custom.snowflakecomputing.com');
  });

  test('throws FatalError when OAUTH_TOKEN is missing', async () => {
    await expect(
      script.invoke(
        { snowflake_user: 'alice', resource_type: 'Engineering', action: 'grant' },
        makeContext({ OAUTH_TOKEN: undefined })
      )
    ).rejects.toThrow('OAUTH_TOKEN environment variable is required');
  });

  test('throws FatalError for unknown action', async () => {
    await expect(
      script.invoke(
        { snowflake_user: 'alice', resource_type: 'Engineering', action: 'unknown' },
        makeContext()
      )
    ).rejects.toThrow('action must be one of');
  });

  test('throws FatalError when snowflake_user is missing', async () => {
    await expect(
      script.invoke(
        { resource_type: 'Engineering', action: 'grant' },
        makeContext()
      )
    ).rejects.toThrow('snowflake_user is required');
  });

  test('throws FatalError when resource_type missing for grant', async () => {
    await expect(
      script.invoke(
        { snowflake_user: 'alice', action: 'grant' },
        makeContext()
      )
    ).rejects.toThrow('resource_type is required');
  });

  test('retries on 429 rate limit response', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 429,
      text: async () => 'rate limited',
    });

    await expect(
      script.invoke(
        { snowflake_user: 'alice', resource_type: 'Engineering', action: 'grant' },
        makeContext()
      )
    ).rejects.toThrow('rate limit');
  });

  test('throws FatalError on 401 auth failure', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 401,
      text: async () => 'unauthorized',
    });

    await expect(
      script.invoke(
        { snowflake_user: 'alice', resource_type: 'Engineering', action: 'grant' },
        makeContext()
      )
    ).rejects.toThrow('401');
  });
});

describe('error handler', () => {
  test('rethrows the error', async () => {
    await expect(
      script.error({ error: new Error('something went wrong') }, {})
    ).rejects.toThrow('something went wrong');
  });
});

describe('halt handler', () => {
  test('returns halted status', async () => {
    const result = await script.halt({ reason: 'timeout' }, {});
    expect(result.status).toBe('halted');
    expect(result.reason).toBe('timeout');
    expect(result.halted_at).toBeDefined();
  });
});
