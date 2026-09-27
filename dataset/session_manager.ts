import express from 'express';
import fs from 'fs';
import path from 'path';

const app = express();

app.get('/download', (req, res) => {
    const fileName = req.query.file as string;
    const filePath = path.join(__dirname, 'uploads', fileName);

    const content = fs.readFileSync(filePath);
    res.send(content);
});

app.listen(3000, () => console.log('Server running'));
