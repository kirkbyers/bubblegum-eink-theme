/**
 * JavaScript Sample File for Theme Testing
 * This file contains various JavaScript constructs to test syntax highlighting
 */

// Import statements
import { Component } from 'react';
import axios from 'axios';

// Constants and variables
const API_URL = 'https://api.example.com';
let counter = 0;
var globalVar = null;

// Class definition
class UserManager {
    constructor(apiUrl) {
        this.apiUrl = apiUrl;
        this.users = [];
    }

    // Async method with error handling
    async fetchUsers() {
        try {
            const response = await axios.get(`${this.apiUrl}/users`);
            this.users = response.data;
            return this.users;
        } catch (error) {
            console.error('Failed to fetch users:', error.message);
            throw new Error('User fetch failed');
        }
    }

    // Method with various data types
    processUser(user) {
        const { id, name, email, isActive = true } = user;
        
        if (!name || typeof name !== 'string') {
            return false;
        }

        // Regular expression
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        
        return {
            id: parseInt(id),
            name: name.trim(),
            email: emailRegex.test(email) ? email : null,
            isActive,
            createdAt: new Date().toISOString()
        };
    }
}

// Function declaration with template literals
function generateReport(users, options = {}) {
    const { format = 'json', includeInactive = false } = options;
    
    let filteredUsers = users;
    if (!includeInactive) {
        filteredUsers = users.filter(user => user.isActive);
    }

    // Switch statement
    switch (format) {
        case 'json':
            return JSON.stringify(filteredUsers, null, 2);
        case 'csv':
            return filteredUsers.map(u => `${u.id},${u.name},${u.email}`).join('\n');
        default:
            throw new Error(`Unsupported format: ${format}`);
    }
}

// Arrow functions and array methods
const userManager = new UserManager(API_URL);
const activeUsers = (users) => users.filter(user => user.isActive);
const userCount = (users) => users.length;

// Event handling
document.addEventListener('DOMContentLoaded', () => {
    const button = document.getElementById('load-users');
    
    button?.addEventListener('click', async (event) => {
        event.preventDefault();
        
        try {
            const users = await userManager.fetchUsers();
            const report = generateReport(users, { format: 'json' });
            
            console.log(`Loaded ${userCount(users)} users`);
            console.log(report);
        } catch (error) {
            alert(`Error: ${error.message}`);
        }
    });
});

// Export
export { UserManager, generateReport, activeUsers };
export default userManager;