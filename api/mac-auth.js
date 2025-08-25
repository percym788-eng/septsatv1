// api/mac-auth.js - MAC Authentication API Handler (Server Only)
import MACDatabase from '../mac-database.js';
import crypto from 'crypto';

// Initialize database
const macDB = new MACDatabase();

// Admin authentication helper
function verifyAdminKey(adminKey, requiredKey) {
    if (!adminKey || !requiredKey) {
        return false;
    }
    return adminKey === requiredKey;
}

// Request validation helper
function validateMACAddress(macAddress) {
    const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
    return macRegex.test(macAddress);
}

// Rate limiting helper (simple in-memory store)
const rateLimitStore = new Map();
const RATE_LIMIT = 60; // requests per hour
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour in milliseconds

function checkRateLimit(identifier) {
    const now = Date.now();
    const key = identifier;
    
    if (!rateLimitStore.has(key)) {
        rateLimitStore.set(key, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
        return true;
    }
    
    const entry = rateLimitStore.get(key);
    
    if (now > entry.resetTime) {
        entry.count = 1;
        entry.resetTime = now + RATE_LIMIT_WINDOW;
        return true;
    }
    
    if (entry.count >= RATE_LIMIT) {
        return false;
    }
    
    entry.count++;
    return true;
}

// Security logging
function logSecurityEvent(event, details, ip = 'unknown') {
    const timestamp = new Date().toISOString();
    console.log(`[SECURITY] ${timestamp} | IP: ${ip} | Event: ${event} | Details: ${details}`);
}

// Main API handler
export default async function handler(req, res) {
    const { method, query, body } = req;
    const action = query.action;
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    try {
        // Basic rate limiting
        if (!checkRateLimit(clientIP)) {
            logSecurityEvent('RATE_LIMIT_EXCEEDED', 'Too many requests', clientIP);
            return res.status(429).json({
                success: false,
                message: 'Too many requests. Please try again later.'
            });
        }
        
        // Handle different actions
        switch (action) {
            case 'check-access':
                return await handleCheckAccess(req, res, clientIP);
            case 'add-mac':
                return await handleAddMAC(req, res, clientIP);
            case 'update-access':
                return await handleUpdateAccess(req, res, clientIP);
            case 'remove-mac':
                return await handleRemoveMAC(req, res, clientIP);
            case 'list-macs':
                return await handleListMACs(req, res, clientIP);
            case 'bulk-add':
                return await handleBulkAdd(req, res, clientIP);
            default:
                logSecurityEvent('INVALID_ACTION', `Unknown action: ${action}`, clientIP);
                return res.status(400).json({
                    success: false,
                    message: 'Invalid action specified'
                });
        }
    } catch (error) {
        console.error('API Error:', error);
        logSecurityEvent('API_ERROR', error.message, clientIP);
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
}

// Check MAC address access
async function handleCheckAccess(req, res, clientIP) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { macAddresses, deviceInfo } = req.body;
    
    if (!macAddresses || !Array.isArray(macAddresses) || macAddresses.length === 0) {
        logSecurityEvent('INVALID_REQUEST', 'Missing or invalid MAC addresses', clientIP);
        return res.status(400).json({
            success: false,
            message: 'MAC addresses are required'
        });
    }
    
    if (!deviceInfo) {
        logSecurityEvent('INVALID_REQUEST', 'Missing device info', clientIP);
        return res.status(400).json({
            success: false,
            message: 'Device information is required'
        });
    }
    
    // Validate MAC addresses
    for (const mac of macAddresses) {
        if (!validateMACAddress(mac)) {
            logSecurityEvent('INVALID_MAC', `Invalid MAC format: ${mac}`, clientIP);
            return res.status(400).json({
                success: false,
                message: `Invalid MAC address format: ${mac}`
            });
        }
    }
    
    deviceInfo.clientIP = clientIP;
    
    try {
        const result = await macDB.checkAccess(macAddresses, deviceInfo);
        
        if (result.success) {
            logSecurityEvent('ACCESS_GRANTED', `MAC: ${macAddresses[0]}, Device: ${deviceInfo.hostname}`, clientIP);
        } else {
            logSecurityEvent('ACCESS_DENIED', `MAC: ${macAddresses[0]}, Device: ${deviceInfo.hostname}`, clientIP);
        }
        
        return res.status(200).json(result);
    } catch (error) {
        logSecurityEvent('DATABASE_ERROR', error.message, clientIP);
        return res.status(500).json({
            success: false,
            message: 'Database error occurred'
        });
    }
}

// Add MAC address to whitelist (Admin only)
async function handleAddMAC(req, res, clientIP) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { macAddress, description, accessType = 'trial', adminKey } = req.body;
    
    const requiredAdminKey = process.env.ADMIN_SECRET_KEY || 'default-admin-key-change-me';
    if (!verifyAdminKey(adminKey, requiredAdminKey)) {
        logSecurityEvent('UNAUTHORIZED_ADMIN', 'Invalid admin key provided', clientIP);
        return res.status(401).json({
            success: false,
            message: 'Unauthorized: Invalid admin credentials'
        });
    }
    
    if (!macAddress || !description) {
        return res.status(400).json({
            success: false,
            message: 'MAC address and description are required'
        });
    }
    
    if (!validateMACAddress(macAddress)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid MAC address format'
        });
    }
    
    if (!['trial', 'unlimited', 'admin'].includes(accessType)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid access type. Must be: trial, unlimited, or admin'
        });
    }
    
    try {
        const result = await macDB.addMACAddress(macAddress, description, accessType);
        
        if (result.success) {
            logSecurityEvent('MAC_ADDED', `MAC: ${macAddress}, Type: ${accessType}, Desc: ${description}`, clientIP);
        }
        
        return res.status(result.success ? 200 : 400).json(result);
    } catch (error) {
        logSecurityEvent('DATABASE_ERROR', error.message, clientIP);
        return res.status(500).json({
            success: false,
            message: 'Database error occurred'
        });
    }
}

// Update MAC address access type (Admin only)
async function handleUpdateAccess(req, res, clientIP) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { macAddress, accessType, adminKey } = req.body;
    
    const requiredAdminKey = process.env.ADMIN_SECRET_KEY || 'default-admin-key-change-me';
    if (!verifyAdminKey(adminKey, requiredAdminKey)) {
        logSecurityEvent('UNAUTHORIZED_ADMIN', 'Invalid admin key for update', clientIP);
        return res.status(401).json({
            success: false,
            message: 'Unauthorized: Invalid admin credentials'
        });
    }
    
    if (!macAddress || !accessType) {
        return res.status(400).json({
            success: false,
            message: 'MAC address and access type are required'
        });
    }
    
    if (!validateMACAddress(macAddress)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid MAC address format'
        });
    }
    
    if (!['trial', 'unlimited', 'admin'].includes(accessType)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid access type. Must be: trial, unlimited, or admin'
        });
    }
    
    try {
        const result = await macDB.updateMACAccess(macAddress, accessType);
        
        if (result.success) {
            logSecurityEvent('MAC_UPDATED', `MAC: ${macAddress}, New Type: ${accessType}`, clientIP);
        }
        
        return res.status(result.success ? 200 : 400).json(result);
    } catch (error) {
        logSecurityEvent('DATABASE_ERROR', error.message, clientIP);
        return res.status(500).json({
            success: false,
            message: 'Database error occurred'
        });
    }
}

// Remove MAC address from whitelist (Admin only)
async function handleRemoveMAC(req, res, clientIP) {
    if (req.method !== 'DELETE') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { macAddress, adminKey } = req.body;
    
    const requiredAdminKey = process.env.ADMIN_SECRET_KEY || 'default-admin-key-change-me';
    if (!verifyAdminKey(adminKey, requiredAdminKey)) {
        logSecurityEvent('UNAUTHORIZED_ADMIN', 'Invalid admin key for removal', clientIP);
        return res.status(401).json({
            success: false,
            message: 'Unauthorized: Invalid admin credentials'
        });
    }
    
    if (!macAddress) {
        return res.status(400).json({
            success: false,
            message: 'MAC address is required'
        });
    }
    
    if (!validateMACAddress(macAddress)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid MAC address format'
        });
    }
    
    try {
        const result = await macDB.removeMACAddress(macAddress);
        
        if (result.success) {
            logSecurityEvent('MAC_REMOVED', `MAC: ${macAddress}`, clientIP);
        }
        
        return res.status(result.success ? 200 : 400).json(result);
    } catch (error) {
        logSecurityEvent('DATABASE_ERROR', error.message, clientIP);
        return res.status(500).json({
            success: false,
            message: 'Database error occurred'
        });
    }
}

// List all MAC addresses (Admin only)
async function handleListMACs(req, res, clientIP) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { adminKey } = req.body;
    
    const requiredAdminKey = process.env.ADMIN_SECRET_KEY || 'default-admin-key-change-me';
    if (!verifyAdminKey(adminKey, requiredAdminKey)) {
        logSecurityEvent('UNAUTHORIZED_ADMIN', 'Invalid admin key for listing', clientIP);
        return res.status(401).json({
            success: false,
            message: 'Unauthorized: Invalid admin credentials'
        });
    }
    
    try {
        const result = await macDB.listMACAddresses();
        
        if (result.success) {
            logSecurityEvent('MAC_LIST_ACCESSED', `Retrieved ${result.data.macAddresses.length} entries`, clientIP);
        }
        
        return res.status(200).json(result);
    } catch (error) {
        logSecurityEvent('DATABASE_ERROR', error.message, clientIP);
        return res.status(500).json({
            success: false,
            message: 'Database error occurred'
        });
    }
}

// Bulk add MAC addresses (Admin only)
async function handleBulkAdd(req, res, clientIP) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { macAddresses, adminKey } = req.body;
    
    const requiredAdminKey = process.env.ADMIN_SECRET_KEY || 'default-admin-key-change-me';
    if (!verifyAdminKey(adminKey, requiredAdminKey)) {
        logSecurityEvent('UNAUTHORIZED_ADMIN', 'Invalid admin key for bulk add', clientIP);
        return res.status(401).json({
            success: false,
            message: 'Unauthorized: Invalid admin credentials'
        });
    }
    
    if (!macAddresses || !Array.isArray(macAddresses) || macAddresses.length === 0) {
        return res.status(400).json({
            success: false,
            message: 'MAC addresses array is required'
        });
    }
    
    for (const entry of macAddresses) {
        if (!entry.macAddress || !validateMACAddress(entry.macAddress)) {
            return res.status(400).json({
                success: false,
                message: `Invalid MAC address: ${entry.macAddress}`
            });
        }
        
        if (entry.accessType && !['trial', 'unlimited', 'admin'].includes(entry.accessType)) {
            return res.status(400).json({
                success: false,
                message: `Invalid access type for ${entry.macAddress}: ${entry.accessType}`
            });
        }
    }
    
    try {
        const result = await macDB.bulkAddMACs(macAddresses);
        
        if (result.success) {
            logSecurityEvent('BULK_ADD', `Added ${result.data.summary.added} MACs`, clientIP);
        }
        
        return res.status(result.success ? 200 : 400).json(result);
    } catch (error) {
        logSecurityEvent('DATABASE_ERROR', error.message, clientIP);
        return res.status(500).json({
            success: false,
            message: 'Database error occurred'
        });
    }
}
