import { app } from './src/app.js';
import { PORT } from './src/config.js';
import { startPolling } from './src/polling.js';
import 'dotenv/config';

app.listen(PORT, () => {
  console.log(`\n  Kaspi Pay App running at http://localhost:${PORT}\n`);
  startPolling();
});
