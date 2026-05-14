import express from 'express';
import path from 'path';
import { ROOT_DIR } from './config.js';
import authRoutes from './routes/auth.js';
import invoiceRoutes from './routes/invoice.js';
import qrRoutes from './routes/qr.js';
import historyRoutes from './routes/history.js';
import refundRoutes from './routes/refund.js';
import sessionRoutes from './routes/session.js';

export const app = express();

app.use(express.json());
app.use(express.static(path.join(ROOT_DIR, 'public')));

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/api/auth', authRoutes);
app.use('/api/invoice', invoiceRoutes);
app.use('/api/qr', qrRoutes);
app.use('/api/history', historyRoutes);
app.use('/api/refund', refundRoutes);
app.use('/api/session', sessionRoutes);

export default app;
