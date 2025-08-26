// api/mac-auth-enhanced.js - Enhanced MAC Address Authentication with Multiple Persistence Strategies
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

// Multiple persistence strategies to handle Vercel's limitations
const STRATEGIES = {
    PRIMARY: path.join(process.cwd(), 'data', 'mac-whitelist.json'),
    BACKUP: path.join('/tmp', 'mac-whitelist.json'),
    FALLBACK: path.join('/tmp', 'mac-backup.json'),
    MEMORY_BACKUP: null // Will be set to in-memory backup
};

let memoryStore = {
    macAddresses: new Map(),
    statistics: {
        total: 0,
        activeLast24h: 0,
        activeLast7d: 0,
        neverUsed: 0,
        totalAccesses: 0
    },
    lastLoaded: null,
    initialized: false
};

// Initialize storage system
async function initializeStorage() {
    if (memoryStore.initialized) return;
    
    console.log('🔄 Initializing MAC address storage system...');
    
    try {
        await loadFromStorage();
        memoryStore.initialized = true;
        console.log(`✅ Storage initialized with ${memoryStore.macAddresses.size} MAC addresses`);
    } catch (error) {
        console.error('❌ Storage initialization failed:', error);
        // Continue with empty store
        memoryStore.initialized = true;
    }
}

// Load data from multiple sources with fallback strategy
async function loadFromStorage() {
    const sources = [
        { name: 'Primary', path: STRATEGIES.PRIMARY },
        { name: 'Backup', path: STRATEGIES.BACKUP },
        { name: 'Fallback', path: STRATEGIES.FALLBACK }
    ];
    
    for (const source of sources) {
        try {
            const data = await fs.readFile(source.path, 'utf8');
            const parsed = JSON.parse(data);
            
            if (parsed.macAddresses && Array.isArray(parsed.macAddresses)) {
                console.log(`📂 Loading from ${source.name}: ${source.path}`);
                
                // Clear and populate memory store
                memoryStore.macAddresses.clear();
                parsed.macAddresses.forEach(entry => {
                    memoryStore.macAddresses.set(entry.macAddress, entry);
                });
                
                // Update statistics
                if (parsed.statistics) {
                    memoryStore.statistics = { ...memoryStore.statistics, ...parsed.statistics };
                }
                
                memoryStore.lastLoaded = new Date().toISOString();
                console.log(`✅ Loaded ${memoryStore.macAddresses.size} MAC addresses from ${source.name}`);
                return; // Success, stop trying other sources
            }
        } catch (error) {
            console.log(`⚠️  Failed to load from ${source.name} (${source.path}): ${error.message}`);
            continue; // Try next source
        }
    }
    
    // If all sources failed, start with empty store
    console.log('📝 Starting with empty MAC whitelist');
    memoryStore.macAddresses.clear();
}

// Save data to multiple locations for redundancy
async function saveToStorage() {
    const data = {
        macAddresses: Array.from(memoryStore.macAddresses.values()),
        statistics: memoryStore.statistics,
        lastUpdated: new Date().toISOString(),
        version: '2.0'
    };
    
    const jsonData = JSON.stringify(data, null, 2);
    const results = [];
    
    // Try to save to all locations
    const targets = [
        { name: 'Primary', path: STRATEGIES.PRIMARY },
        { name: 'Backup', path: STRATEGIES.BACKUP },
        { name: 'Fallback', path: STRATEGIES.FALLBACK }
    ];
    
    for (const target of targets) {
        try {
            // Ensure directory exists for primary location
            if (target.name === 'Primary') {
                await fs.mkdir(path.dirname(target.path), { recursive: true });
            }
            
            await fs.writeFile(target.path, jsonData);
            results.push({ name: target.name, success: true });
            console.log(`💾 Saved to ${target.name}: ${target.path}`);
        } catch (error) {
            results.push({ name: target.name, success: false, error: error.message });
            console.log(`❌ Failed to save to ${target.name}: ${error.message}`);
        }
    }
    
    // Always keep in-memory backup
    STRATEGIES.MEMORY_BACKUP = data;
    
    const successCount = results.filter(r => r.success).length;
    console.log(`Saved to ${successCount}/${targets.length} storage locations`);
    
    return successCount > 0; // Return true if at least one save succeeded
}

// Update statistics based on current data
function updateStatistics() {
    const now = Date.now();
    const oneDayAgo = now - (24 * 60 * 60 * 1000);
    const oneWeekAgo = now - (7 * 24 * 60 * 60 * 1000);
    
    memoryStore.statistics.total = memoryStore.macAddresses.size;
    memoryStore.statistics.activeLast24h = 0;
    memoryStore.statistics.activeLast7d = 0;
    memoryStore.statistics.neverUsed = 0;
    memoryStore.statistics.totalAccesses = 0;
    
    for (const entry of memoryStore.macAddresses.values()) {
        const lastSeen = entry.lastSeen ? new Date(entry.lastSeen).getTime() : 0;
        memoryStore.statistics.totalAccesses += entry.accessCount || 0;
        
        if (lastSeen === 0) {
            memoryStore.statistics.neverUsed++;
        } else {
            if (lastSeen > oneDayAgo) {
                memoryStore.statistics.activeLast24h++;
            }
            if (lastSeen > oneWeekAgo) {
                memoryStore.statistics.activeLast7d++;
            }
        }
    }
}

// Validate admin key
function validateAdminKey(providedKey) {
    const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || "default-admin-key-change-this";
    return providedKey === ADMIN_SECRET_KEY;
}

// Main API handler
export default async function handler(req, res) {
    // Initialize storage system
    await initializeStorage();
    
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
            case 'health':
                return await handleHealthCheck(req, res);
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

// Health check endpoint
async function handleHealthCheck(req, res) {
    return res.status(200).json({
        success: true,
        message: 'API is healthy',
        data: {
            initialized: memoryStore.initialized,
            totalMACs: memoryStore.macAddresses.size,
            lastLoaded: memoryStore.lastLoaded,
            timestamp: new Date().toISOString()
        }
    });
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
        if (memoryStore.macAddresses.has(normalizedMac)) {
            authorizedEntry = memoryStore.macAddresses.get(normalizedMac);
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
    
    // Save updated data (async, don't wait)
    saveToStorage().catch(error => {
        console.error('Failed to save after access check:', error);
    });
    
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
    
    if (memoryStore.macAddresses.has(normalizedMac)) {
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
    
    memoryStore.macAddresses.set(normalizedMac, entry);
    
    // Save to storage
    const saved = await saveToStorage();
    if (!saved) {
        console.error('WARNING: MAC address added to memory but failed to persist to storage');
    }
    
    return res.status(201).json({
        success: true,
        message: 'MAC address added successfully',
        data: entry,
        persistent: saved
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
    
    if (!memoryStore.macAddresses.has(normalizedMac)) {
        return res.status(404).json({
            success: false,
            message: 'MAC address not found in whitelist'
        });
    }
    
    const entry = memoryStore.macAddresses.get(normalizedMac);
    entry.accessType = accessType;
    entry.updatedAt = new Date().toISOString();
    
    // Save to storage
    const saved = await saveToStorage();
    
    return res.status(200).json({
        success: true,
        message: 'Access type updated successfully',
        data: entry,
        persistent: saved
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
    
    if (!memoryStore.macAddresses.has(normalizedMac)) {
        return res.status(404).json({
            success: false,
            message: 'MAC address not found in whitelist'
        });
    }
    
    memoryStore.macAddresses.delete(normalizedMac);
    
    // Save to storage
    const saved = await saveToStorage();
    
    return res.status(200).json({
        success: true,
        message: 'MAC address removed successfully',
        persistent: saved
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
            macAddresses: Array.from(memoryStore.macAddresses.values()).sort((a, b) => 
                new Date(b.addedAt) - new Date(a.addedAt)
            ),
            statistics: memoryStore.statistics
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
        
        if (memoryStore.macAddresses.has(normalizedMac)) {
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
        
        memoryStore.macAddresses.set(normalizedMac, entry);
        results.push({ macAddress: normalizedMac, success: true, message: 'Added successfully' });
        addedCount++;
    }
    
    // Save to storage if any were added
    let saved = false;
    if (addedCount > 0) {
        saved = await saveToStorage();
    }
    
    return res.status(200).json({
        success: true,
        message: `Bulk add completed. ${addedCount} MAC addresses added.`,
        data: {
            results: results,
            totalProcessed: macAddresses.length,
            totalAdded: addedCount
        },
        persistent: saved
    });
}
