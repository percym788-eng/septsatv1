// api/mac-auth.js - MAC Address Authentication API with File-Based Persistence
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

// Storage configuration - use multiple persistence strategies
const DATA_FILE = path.join(process.cwd(), 'data', 'mac-whitelist.json');
const BACKUP_FILE = path.join('/tmp', 'mac-whitelist-backup.json');

// Initialize data structure
let macWhitelist = new Map();
let statistics = {
    total: 0,
    activeLast24h: 0,
    activeLast7d: 0,
    neverUsed: 0,
    totalAccesses: 0
};

// Ensure data directory exists
async function ensureDataDirectory() {
    try {
        const dataDir = path.dirname(DATA_FILE);
        await fs.mkdir(dataDir, { recursive: true });
        console.log('Data directory ensured:', dataDir);
    } catch (error) {
        console.log('Data directory creation skipped:', error.message);
    }
}

// Load MAC whitelist from persistent storage
async function loadMACWhitelist() {
    try {
        // Try to load from main data file first
        await ensureDataDirectory();
        
        let data;
        try {
            const fileData = await fs.readFile(DATA_FILE, 'utf8');
            data = JSON.parse(fileData);
            console.log('MAC whitelist loaded from main data file');
        } catch (mainError) {
            // Fallback to backup file
            try {
                const backupData = await fs.readFile(BACKUP_FILE, 'utf8');
                data = JSON.parse(backupData);
                console.log('MAC whitelist loaded from backup file');
                
                // Try to restore main file from backup
                try {
                    await fs.writeFile(DATA_FILE, backupData);
                    console.log('Main data file restored from backup');
                } catch (restoreError) {
                    console.log('Could not restore main file:', restoreError.message);
                }
            } catch (backupError) {
                // No existing data, start fresh
                console.log('No existing MAC whitelist found, starting fresh');
                data = { macAddresses: [], statistics: statistics };
            }
        }
        
        // Convert array to Map for efficient lookups
        macWhitelist.clear();
        if (data.macAddresses && Array.isArray(data.macAddresses)) {
            data.macAddresses.forEach(entry => {
                macWhitelist.set(entry.macAddress, entry);
            });
        }
        
        // Update statistics
        if (data.statistics) {
            statistics = { ...statistics, ...data.statistics };
        }
        
        console.log(`Loaded ${macWhitelist.size} MAC addresses from storage`);
        
    } catch (error) {
        console.error('Error loading MAC whitelist:', error);
        // Start with empty whitelist if loading fails
        macWhitelist.clear();
    }
}

// Save MAC whitelist to persistent storage
async function saveMACWhitelist() {
    const data = {
        macAddresses: Array.from(macWhitelist.values()),
        statistics: statistics,
        lastUpdated: new Date().toISOString(),
        version: '1.0'
    };
    
    const jsonData = JSON.stringify(data, null, 2);
    
    try {
        // Save to main file
        await ensureDataDirectory();
        await fs.writeFile(DATA_FILE, jsonData);
        console.log('MAC whitelist saved to main data file');
    } catch (error) {
        console.log('Could not save to main file:', error.message);
    }
    
    try {
        // Always save backup
        await fs.writeFile(BACKUP_FILE, jsonData);
        console.log('MAC whitelist backup saved');
    } catch (error) {
        console.log('Could not save backup:', error.message);
    }
}

// Update statistics
function updateStatistics() {
    const now = Date.now();
    const oneDayAgo = now - (24 * 60 * 60 * 1000);
    const oneWeekAgo = now - (7 * 24 * 60 * 60 * 1000);
    
    statistics.total = macWhitelist.size;
    statistics.activeLast24h = 0;
    statistics.activeLast7d = 0;
    statistics.neverUsed = 0;
    statistics.totalAccesses = 0;
    
    for (const entry of macWhitelist.values()) {
        const lastSeen = entry.lastSeen ? new Date(entry.lastSeen).getTime() : 0;
        statistics.totalAccesses += entry.accessCount || 0;
        
        if (lastSeen === 0) {
            statistics.neverUsed++;
        } else {
            if (lastSeen > oneDayAgo) {
                statistics.activeLast24h++;
            }
            if (lastSeen > oneWeekAgo) {
                statistics.activeLast7d++;
            }
        }
    }
}

// Validate admin key
function validateAdminKey(providedKey) {
    // In production, you should set this as an environment variable
    const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || "default-admin-key-change-this";
    return providedKey === ADMIN_SECRET_KEY;
}

// Main API handler
export default async function handler(req, res) {
    // Load MAC whitelist at the start of each request
    await loadMACWhitelist();
    
    // Handle CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    const { action } = req.query;
    
    try {
        switch (action) {
            case 'check-access':
                return await handleCheckAccess(req, res);
            case 'add-mac':
                return await handleAddMAC(req, res);
            case 'update-access':
                return await handleUpdateAccess(req, res);
            case 'remove-mac':
                return await handleRemoveMAC(req, res);
            case 'list-macs':
                return await handleListMACs(req, res);
            case 'bulk-add':
                return await handleBulkAdd(req, res);
            default:
                return res.status(400).json({
                    success: false,
                    message: 'Invalid action'
                });
        }
    } catch (error) {
        console.error('API Error:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
}

// Check if MAC address has access
async function handleCheckAccess(req, res) {
    const { macAddresses, deviceInfo } = req.body;
    
    if (!macAddresses || !Array.isArray(macAddresses) || macAddresses.length === 0) {
        return res.status(400).json({
            success: false,
            message: 'MAC addresses are required'
        });
    }
    
    // Check if any of the provided MAC addresses are whitelisted
    let authorizedEntry = null;
    for (const macAddress of macAddresses) {
        const normalizedMac = macAddress.toLowerCase();
        if (macWhitelist.has(normalizedMac)) {
            authorizedEntry = macWhitelist.get(normalizedMac);
            break;
        }
    }
    
    if (!authorizedEntry) {
        return res.status(403).json({
            success: false,
            message: 'Device not authorized. MAC address not in whitelist.',
            data: null
        });
    }
    
    // Update last seen and access count
    authorizedEntry.lastSeen = new Date().toISOString();
    authorizedEntry.accessCount = (authorizedEntry.accessCount || 0) + 1;
    
    // Update device info if provided
    if (deviceInfo) {
        authorizedEntry.lastDevice = {
            hostname: deviceInfo.hostname,
            username: deviceInfo.username,
            platform: deviceInfo.platform,
            localIP: deviceInfo.localIP,
            publicIP: deviceInfo.publicIP
        };
    }
    
    // Save updated data
    await saveMACWhitelist();
    
    return res.status(200).json({
        success: true,
        message: 'Device authorized',
        data: {
            macAddress: authorizedEntry.macAddress,
            description: authorizedEntry.description,
            accessType: authorizedEntry.accessType || 'trial',
            addedAt: authorizedEntry.addedAt,
            lastSeen: authorizedEntry.lastSeen,
            accessCount: authorizedEntry.accessCount
        }
    });
}

// Add MAC address to whitelist
async function handleAddMAC(req, res) {
    const { macAddress, description, accessType, adminKey } = req.body;
    
    if (!validateAdminKey(adminKey)) {
        return res.status(403).json({
            success: false,
            message: 'Invalid admin key'
        });
    }
    
    if (!macAddress) {
        return res.status(400).json({
            success: false,
            message: 'MAC address is required'
        });
    }
    
    const normalizedMac = macAddress.toLowerCase();
    const validAccessTypes = ['trial', 'unlimited', 'admin'];
    const finalAccessType = validAccessTypes.includes(accessType) ? accessType : 'trial';
    
    if (macWhitelist.has(normalizedMac)) {
        return res.status(409).json({
            success: false,
            message: 'MAC address already exists in whitelist'
        });
    }
    
    const entry = {
        macAddress: normalizedMac,
        description: description || 'No description',
        accessType: finalAccessType,
        addedAt: new Date().toISOString(),
        lastSeen: null,
        accessCount: 0,
        lastDevice: null
    };
    
    macWhitelist.set(normalizedMac, entry);
    await saveMACWhitelist();
    
    return res.status(201).json({
        success: true,
        message: 'MAC address added successfully',
        data: entry
    });
}

// Update access type for existing MAC
async function handleUpdateAccess(req, res) {
    const { macAddress, accessType, adminKey } = req.body;
    
    if (!validateAdminKey(adminKey)) {
        return res.status(403).json({
            success: false,
            message: 'Invalid admin key'
        });
    }
    
    if (!macAddress || !accessType) {
        return res.status(400).json({
            success: false,
            message: 'MAC address and access type are required'
        });
    }
    
    const normalizedMac = macAddress.toLowerCase();
    const validAccessTypes = ['trial', 'unlimited', 'admin'];
    
    if (!validAccessTypes.includes(accessType)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid access type. Must be: trial, unlimited, or admin'
        });
    }
    
    if (!macWhitelist.has(normalizedMac)) {
        return res.status(404).json({
            success: false,
            message: 'MAC address not found in whitelist'
        });
    }
    
    const entry = macWhitelist.get(normalizedMac);
    entry.accessType = accessType;
    entry.updatedAt = new Date().toISOString();
    
    await saveMACWhitelist();
    
    return res.status(200).json({
        success: true,
        message: 'Access type updated successfully',
        data: entry
    });
}

// Remove MAC address from whitelist
async function handleRemoveMAC(req, res) {
    const { macAddress, adminKey } = req.body;
    
    if (!validateAdminKey(adminKey)) {
        return res.status(403).json({
            success: false,
            message: 'Invalid admin key'
        });
    }
    
    if (!macAddress) {
        return res.status(400).json({
            success: false,
            message: 'MAC address is required'
        });
    }
    
    const normalizedMac = macAddress.toLowerCase();
    
    if (!macWhitelist.has(normalizedMac)) {
        return res.status(404).json({
            success: false,
            message: 'MAC address not found in whitelist'
        });
    }
    
    macWhitelist.delete(normalizedMac);
    await saveMACWhitelist();
    
    return res.status(200).json({
        success: true,
        message: 'MAC address removed successfully'
    });
}

// List all MAC addresses (admin only)
async function handleListMACs(req, res) {
    const { adminKey } = req.body;
    
    if (!validateAdminKey(adminKey)) {
        return res.status(403).json({
            success: false,
            message: 'Invalid admin key'
        });
    }
    
    updateStatistics();
    
    return res.status(200).json({
        success: true,
        message: 'MAC addresses retrieved successfully',
        data: {
            macAddresses: Array.from(macWhitelist.values()).sort((a, b) => 
                new Date(b.addedAt) - new Date(a.addedAt)
            ),
            statistics: statistics
        }
    });
}

// Bulk add MAC addresses
async function handleBulkAdd(req, res) {
    const { macAddresses, adminKey } = req.body;
    
    if (!validateAdminKey(adminKey)) {
        return res.status(403).json({
            success: false,
            message: 'Invalid admin key'
        });
    }
    
    if (!macAddresses || !Array.isArray(macAddresses)) {
        return res.status(400).json({
            success: false,
            message: 'MAC addresses array is required'
        });
    }
    
    const results = [];
    let addedCount = 0;
    
    for (const macData of macAddresses) {
        const { macAddress, description, accessType } = macData;
        const normalizedMac = macAddress ? macAddress.toLowerCase() : '';
        const finalAccessType = ['trial', 'unlimited', 'admin'].includes(accessType) ? accessType : 'trial';
        
        if (!macAddress) {
            results.push({ macAddress: macAddress || 'invalid', success: false, message: 'Invalid MAC address' });
            continue;
        }
        
        if (macWhitelist.has(normalizedMac)) {
            results.push({ macAddress: normalizedMac, success: false, message: 'Already exists' });
            continue;
        }
        
        const entry = {
            macAddress: normalizedMac,
            description: description || 'Bulk added',
            accessType: finalAccessType,
            addedAt: new Date().toISOString(),
            lastSeen: null,
            accessCount: 0,
            lastDevice: null
        };
        
        macWhitelist.set(normalizedMac, entry);
        results.push({ macAddress: normalizedMac, success: true, message: 'Added successfully' });
        addedCount++;
    }
    
    if (addedCount > 0) {
        await saveMACWhitelist();
    }
    
    return res.status(200).json({
        success: true,
        message: `Bulk add completed. ${addedCount} MAC addresses added.`,
        data: {
            results: results,
            totalProcessed: macAddresses.length,
            totalAdded: addedCount
        }
    });
}
