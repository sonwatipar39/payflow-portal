import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

// Get current directory name for proper file paths in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create Express app
const app = express();

// Serve static files
app.use(express.static(path.join(__dirname, '.')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    serverTime: new Date().toISOString(),
    message: 'Server is running'
  });
});

// Serve index.html for all routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Working directory: ${process.cwd()}`);
  console.log(`__dirname: ${__dirname}`);
  
  // List files in the current directory
  try {
    const fs = await import('fs');
    const files = fs.readdirSync(process.cwd());
    console.log('Files in working directory:', files);
  } catch (error) {
    console.error('Error listing files:', error);
  }
});
