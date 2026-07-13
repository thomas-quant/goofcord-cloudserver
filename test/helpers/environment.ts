export const validEnvironment = (): Record<string, string> => ({
    CLIENT_ID: 'test-client-id',
    CLIENT_SECRET: 'test-client-secret',
    REDIRECT_URI: 'http://localhost:3000',
    MONGO_URI: 'mongodb://127.0.0.1:27017/goofcord-test',
});
