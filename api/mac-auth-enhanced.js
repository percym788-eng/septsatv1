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
    console.log(`💾
