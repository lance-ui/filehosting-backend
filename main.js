import fetch from 'node-fetch'; 
import fs from 'fs'; 
import { promises as fsp } from 'fs';
import path from 'path';
import FormData from 'form-data'; 

class LanceCDNClient {
    constructor() {
        this.apiKey = null;
        this.baseUrl = null;
        this.isInitialized = false;
    }

    connect(apiKey, deployedUrl) {
        if (!apiKey || !deployedUrl) {
            throw new Error('API Key and deployed URL are required for connection.');
        }
        this.apiKey = apiKey;
        this.baseUrl = deployedUrl.replace(/\/$/, ''); 
        this.isInitialized = true;
        console.log(`LanceCDN connected to: ${this.baseUrl}`);
    }

    _checkInitialized() {
        if (!this.isInitialized) {
            throw new Error('LanceCDN Client is not initialized. Call lancecdn.connect(apiKey, url) first.');
        }
    }

    async _apiCall(endpoint, method = 'GET', data = null) {
        this._checkInitialized();
        const url = `${this.baseUrl}${endpoint}`;

        const options = {
            method: method,
            headers: {
                'x-api-key': this.apiKey,
            },
        };

        if (data instanceof FormData) {
            options.body = data;
        } else if (data) {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(url, options);
            const contentType = response.headers.get('content-type');

            let errorMessage = 'Unknown error';

            if (!response.ok) {
                const errorBody = (contentType && contentType.includes('application/json')) ? await response.json() : await response.text();

                errorMessage = typeof errorBody === 'object' ? errorBody.error : errorBody;

                throw new Error(`API Error ${response.status}: ${errorMessage}`);
            }

            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            }
            return response;

        } catch (error) {
            console.error(`Request to ${url} failed:`, error.message);
            throw error;
        }
    }

    async _resolveIdentifierToId(identifier) {
        const isHash = identifier.length > 10 && !/^\d+$/.test(identifier);

        if (!isHash) {
            return identifier;
        }

        const files = await this._apiCall('/api/files-api', 'GET');
        const file = files.find(f => f.hash === identifier);

        if (!file) {
             throw new Error(`File with hash ${identifier} not found.`);
        }
        return file.id;
    }

    async download(identifier, downloadPath) {
        this._checkInitialized();

        const fileId = await this._resolveIdentifierToId(identifier);

        const files = await this._apiCall('/api/files-api', 'GET');
        const file = files.find(f => f.id === fileId);

        if (!file) {
            throw new Error(`File ID ${fileId} not found.`);
        }
        const hashToUse = file.hash;

        const endpoint = `/download/${hashToUse}`;
        const response = await this._apiCall(endpoint);

        if (response.status === 404) {
             throw new Error(`File with identifier ${identifier} not found.`);
        }

        const contentDisposition = response.headers.get('content-disposition');
        let filename = path.basename(downloadPath);

        if (contentDisposition && contentDisposition.includes('filename=')) {
            const match = contentDisposition.match(/filename="?([^"]+)"?/i);
            if (match && match[1]) {
                filename = match[1];
            }
        }

        const finalPath = path.join(path.dirname(downloadPath), filename);
        await fsp.mkdir(path.dirname(finalPath), { recursive: true }); 

        const writer = fs.createWriteStream(finalPath);
        response.body.pipe(writer);

        return new Promise((resolve, reject) => {
            writer.on('finish', () => resolve(finalPath));
            writer.on('error', reject);
        });
    }

    async upload(filePath) {
        this._checkInitialized();

        const filename = path.basename(filePath);

        try {
            const fileStream = fs.createReadStream(filePath); 

            const formData = new FormData();
            formData.append('file', fileStream, { filename: filename });

            const result = await this._apiCall('/api/upload-api', 'POST', formData);
            return result;
        } catch (error) {
            if (error.code === 'ENOENT') {
                 throw new Error(`Upload failed: File not found at path ${filePath}`);
            }
            throw error;
        }
    }

    async remove(identifier) {
        this._checkInitialized();

        const fileId = await this._resolveIdentifierToId(identifier);

        const endpoint = `/api/files-api/${fileId}`;
        return this._apiCall(endpoint, 'DELETE');
    }

    async rename(identifier, newName) {
        this._checkInitialized();

        const fileId = await this._resolveIdentifierToId(identifier);

        const endpoint = `/api/files-api/${fileId}`;
        return this._apiCall(endpoint, 'PUT', { newName });
    }

    async editContent(identifier, newContent) {
        this._checkInitialized();

        const fileId = await this._resolveIdentifierToId(identifier);

        const endpoint = `/api/files-api/${fileId}/content`;
        return this._apiCall(endpoint, 'PUT', { content: newContent });
    }
}

const clientInstance = new LanceCDNClient();

const lancecdn = {
    connect: clientInstance.connect.bind(clientInstance),
    download: clientInstance.download.bind(clientInstance),
    upload: clientInstance.upload.bind(clientInstance),
    delete: clientInstance.remove.bind(clientInstance),
    rename: clientInstance.rename.bind(clientInstance),
    editContent: clientInstance.editContent.bind(clientInstance),
};

export default lancecdn;
