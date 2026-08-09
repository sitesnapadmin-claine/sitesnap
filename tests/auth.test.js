process.env.SQLITE_PATH = 'test-auth.db';
const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);
fs.rmSync(dbFile, { force: true }); // start clean even if a previous run crashed

const request = require('supertest');
const { app, initDb } = require('../server.js');

beforeAll(async () => {
    await initDb();
});

afterAll(() => {
    fs.rmSync(dbFile, { force: true });
});

describe('registration', () => {
    test('creates an account and returns a token', async () => {
          const res = await request(app)
            .post('/api/auth/register')
            .send({ email: 'claine@example.com', password: 'hunter22' });
          expect(res.status).toBe(200);
          expect(res.body.token).toBeTruthy();
          expect(res.body.email).toBe('claine@example.com');
          expect(res.body.plan).toBe('free');
    });

           test('rejects a duplicate email with 409', async () => {
                 const res = await request(app)
                   .post('/api/auth/register')
                   .send({ email: 'claine@example.com', password: 'anotherpass' });
                 expect(res.status).toBe(409);
           });

           test('rejects a short password', async () => {
                 const res = await request(app)
                   .post('/api/auth/register')
                   .send({ email: 'short@example.com', password: '123' });
                 expect(res.status).toBe(400);
           });

           test('rejects a missing email', async () => {
                 const res = await request(app)
                   .post('/api/auth/register')
                   .send({ password: 'hunter22' });
                 expect(res.status).toBe(400);
           });
});

describe('login', () => {
    test('logs in with the right credentials', async () => {
          const res = await request(app)
            .post('/api/auth/login')
            .send({ email: 'claine@example.com', password: 'hunter22' });
          expect(res.status).toBe(200);
          expect(res.body.token).toBeTruthy();
    });

           test('rejects the wrong password with 401', async () => {
                 const res = await request(app)
                   .post('/api/auth/login')
                   .send({ email: 'claine@example.com', password: 'wrongpass' });
                 expect(res.status).toBe(401);
           });

           test('rejects an email that was never registered', async () => {
                 const res = await request(app)
                   .post('/api/auth/login')
                   .send({ email: 'nope@example.com', password: 'whatever1' });
                 expect(res.status).toBe(401);
           });
});

describe('/api/me', () => {
    let token;
    beforeAll(async () => {
          const res = await request(app)
            .post('/api/auth/login')
            .send({ email: 'claine@example.com', password: 'hunter22' });
          token = res.body.token;
    });

           test('returns the signed-in user with no token 401', async () => {
                 const res = await request(app).get('/api/me');
                 expect(res.status).toBe(401);
           });

           test('returns the signed-in user with a valid token', async () => {
                 const res = await request(app)
                   .get('/api/me')
                   .set('Authorization', `Bearer ${token}`);
                 expect(res.status).toBe(200);
                 expect(res.body.email).toBe('claine@example.com');
                 expect(res.body.plan).toBe('free');
                 // Sensitive fields must never leak
                    expect(res.body.password_hash).toBeUndefined();
           });

           test('rejects a garbage token', async () => {
                 const res = await request(app)
                   .get('/api/me')
                   .set('Authorization', 'Bearer not-a-real-token');
                 expect(res.status).toBe(401);
           });
});
