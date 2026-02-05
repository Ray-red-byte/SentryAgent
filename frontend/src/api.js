import axios from 'axios';

// Create a configured instance
const api = axios.create({
    baseURL: 'http://localhost:8000', // Points to your FastAPI backend
    headers: {
        'Content-Type': 'application/json',
    },
});

export default api;