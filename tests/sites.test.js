process.env.SQLITE_PATH = 'test-sites.db';
const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);
fs.rmSync(dbFile, { force: true });

const request = require('supertest');
const { app, initDb } = require('../server.js');

let tokenA, tokenB;

beforeAll(async () => {
    await initDb();
    const a = await request(app).post('/api/auth/register')
      .send({ email: 'owner@example.com', password: 'hunter22' });
    tokenA = a.body.token;
    const b = await request(app).post('/api/auth/register')
      .send({ email: 'other@example.com', password: 'hunter22' });
    tokenB = b.body.token;
});

afterAll(() => {
    fs.rmSync(dbFile, { force: true });
});

const sampleSite = { bizName: 'Test Biz', industry: 'Photography', designStyle: 'light-airy' };

describe('site save / load', () => {
    let uuid;

           test('requires auth to save a site', async () => {
                 const res = await request(app).post('/api/sites').send({ data: sampleSite });
                 expect(res.status).toBe(401);
           });

           test('saves a site for a signed-in user', async () => {
                 const res = await request(app)
                   .post('/api/sites')
                   .set('Authorization', `Bearer ${tokenA}`)
                   .send({ data: sampleSite });
                 expect(res.status).toBe(200);
                 expect(res.body.uuid).toBeTruthy();
                 uuid = res.body.uuid;
           });

           test('loads the site back by uuid (public, no auth needed for preview data)', async () => {
                 const res = await request(app).get(`/api/sites/${uuid}`);
                 expect(res.status).toBe(200);
                 expect(res.body.bizName).toBe('Test Biz');
           });

           test('returns 404 for a uuid that does not exist', async () => {
                 const res = await request(app).get('/api/sites/does-not-exist');
                 expect(res.status).toBe(404);
           });

           test('the owner can update their own site', async () => {
                 const res = await request(app)
                   .put(`/api/sites/${uuid}`)
                   .set('Authorization', `Bearer ${tokenA}`)
                   .send({ data: { ...sampleSite, bizName: 'Renamed Biz' } });
                 expect(res.status).toBe(200);
                 const check = await request(app).get(`/api/sites/${uuid}`);
                 expect(check.body.bizName).toBe('Renamed Biz');
           });

           test('a different user cannot update someone else\'s site', async () => {
                 const res = await request(app)
                   .put(`/api/sites/${uuid}`)
                   .set('Authorization', `Bearer ${tokenB}`)
                   .send({ data: sampleSite });
                 expect(res.status).toBe(403);
           });

           test('the free plan blocks creating a second site', async () => {
                 const res = await request(app)
                   .post('/api/sites')
                   .set('Authorization', `Bearer ${tokenA}`)
                   .send({ data: sampleSite });
                 expect(res.status).toBe(403);
                 expect(res.body.limitReached).toBe(true);
           });

           test('a different user cannot delete someone else\'s site', async () => {
                 const res = await request(app)
                   .delete(`/api/sites/${uuid}`)
                   .set('Authorization', `Bearer ${tokenB}`);
                 expect(res.status).toBe(403);
           });

           test('the owner can delete their own site', async () => {
                 const res = await request(app)
                   .delete(`/api/sites/${uuid}`)
                   .set('Authorization', `Bearer ${tokenA}`);
                 expect(res.status).toBe(200);
                 const check = await request(app).get(`/api/sites/${uuid}`);
                 expect(check.status).toBe(404);
           });

           test('after deleting, the free plan allows creating a new site again', async () => {
                 const res = await request(app)
                   .post('/api/sites')
                   .set('Authorization', `Bearer ${tokenA}`)
                   .send({ data: sampleSite });
                 expect(res.status).toBe(200);
           });
});
