// mac-database.js - Minimal Server Database (No Desktop Dependencies)
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

class MACDatabase {
    constructor(dbPath = null) {
        // For Vercel, use /tmp directory
        this.dbPath = dbPath || '/tmp/sat-database';
        this.macFile = path.join(this.dbPath, 'mac-whitelist.json');
        this.logFile = path.join(this.dbPath, 'access-log.json');
        
        this.initializeDatabase();
    }
    
    async initializeDatabase() {
        try {
            // Create directories if they don't exist
            await fs.mkdir(this.dbPath, { recursive: true });
            
            // Initialize MAC whitelist file if it doesn't exist
            try {
                await fs.access(this.macFile);
            } catch {
                const initialData = {
                    version: '1.0',
                    created: new Date().toISOString(),
                    macAddresses: {},
                    statistics: {
                        totalDevices: 0,
                        totalAccesses: 0,
                        lastUpdated: new Date().toISOString()
                    }
                };
                await fs.writeFile(this.macFile, JSON.stringify(initialData, null, 2));
            }
            
            // Initialize access log if it doesn't exist
            try {
                await fs.access(this.logFile);
            } catch {
                const initialLog = {
                    version: '1.0',
                    created: new Date().toISOString(),
                    accessEvents: []
                };
                await fs.writeFile(this.logFile, JSON.stringify(initialLog, null, 2));
            }
            
        } catch (error) {
            console.error('Error initializing MAC database:', error);
            throw error;
        }
    }
    
    async readDatabase() {
        try {
            const data = await fs.readFile(this.macFile, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            console.error('Error reading MAC database:', error);
            return {
                version: '1.0',
                created: new Date().toISOString(),
                macAddresses: {},
                statistics: {
                    totalDevices: 0,
                    totalAccesses: 0,
                    lastUpdated: new Date().toISOString()
                }
            };
        }
    }
    
    async writeDatabase(data) {
        try {
            data.statistics.lastUpdated = new Date().toISOString();
            data.statistics.totalDevices = Object.keys(data.macAddresses).length;
            
            await fs.writeFile(this.macFile, JSON.stringify(data, null, 2));
            return true;
        } catch (error) {
            console.error('Error writing MAC database:', error);
            return false;
        }
    }
    
    async logAccess(macAddress, deviceInfo, success = true, message = '') {
        try {
            let logData;
            try {
                const logContent = await fs.readFile(this.logFile, 'utf8');
                logData = JSON.parse(logContent);
            } catch {
                logData = { version: '1.0', created: new Date().toISOString(), accessEvents: [] };
            }
            
            const logEntry = {
                timestamp: new Date().toISOString(),
                macAddress: macAddress,
                deviceInfo: {
                    hostname: deviceInfo.hostname,
                    username: deviceInfo.username,
                    platform: deviceInfo.platform,
                    localIP: deviceInfo.localIP,
                    publicIP: deviceInfo.publicIP
                },
                success: success,
                message: message,
                id: crypto.randomUUID()
            };
            
            logData.accessEvents.push(logEntry);
            
            // Keep only last 500 log entries for Vercel
            if (logData.accessEvents.length > 500) {
                logData.accessEvents = logData.accessEvents.slice(-500);
            }
            
            await fs.writeFile(this.logFile, JSON.stringify(logData, null, 2));
            
        } catch (error) {
            console.error('Error logging access:', error);
        }
    }
    
    async checkAccess(macAddresses, deviceInfo) {
        try {
            const data = await this.readDatabase();
            
            for (const macAddress of macAddresses) {
                const normalizedMac = macAddress.toLowerCase();
                
                if (data.macAddresses[normalizedMac]) {
                    const entry = data.macAddresses[normalizedMac];
                    
                    entry.lastSeen = new Date().toISOString();
                    entry.accessCount = (entry.accessCount || 0) + 1;
                    entry.lastDevice = {
                        hostname: deviceInfo.hostname,
                        username: deviceInfo.username,
                        platform: deviceInfo.platform,
                        localIP: deviceInfo.localIP,
                        publicIP: deviceInfo.publicIP
                    };
                    
                    data.statistics.totalAccesses = (data.statistics.totalAccesses || 0) + 1;
                    
                    await this.writeDatabase(data);
                    await this.logAccess(normalizedMac, deviceInfo, true, 'Access granted');
                    
                    return {
                        success: true,
                        message: 'Device authorized',
                        data: {
                            macAddress: normalizedMac,
                            description: entry.description,
                            accessType: entry.accessType || 'trial',
                            addedAt: entry.addedAt,
                            lastSeen: entry.lastSeen,
                            accessCount: entry.accessCount
                        }
                    };
                }
            }
            
            await this.logAccess(macAddresses[0] || 'unknown', deviceInfo, false, 'MAC address not whitelisted');
            
            return {
                success: false,
                message: 'Device not authorized. MAC address not in whitelist.',
                data: null
            };
            
        } catch (error) {
            console.error('Error checking MAC access:', error);
            await this.logAccess(macAddresses[0] || 'unknown', deviceInfo, false, `Database error: ${error.message}`);
            
            return {
                success: false,
                message: 'Database error occurred',
                data: null
            };
        }
    }
    
    async addMACAddress(macAddress, description, accessType = 'trial') {
        try {
            const normalizedMac = macAddress.toLowerCase();
            const data = await this.readDatabase();
            
            if (data.macAddresses[normalizedMac]) {
                return {
                    success: false,
                    message: 'MAC address already exists in whitelist'
                };
            }
            
            data.macAddresses[normalizedMac] = {
                description: description,
                accessType: accessType,
                addedAt: new Date().toISOString(),
                lastSeen: null,
                accessCount: 0,
                lastDevice: null,
                id: crypto.randomUUID()
            };
            
            const success = await this.writeDatabase(data);
            
            if (success) {
                return {
                    success: true,
                    message: 'MAC address added successfully',
                    data: data.macAddresses[normalizedMac]
                };
            } else {
                return {
                    success: false,
                    message: 'Failed to save to database'
                };
            }
            
        } catch (error) {
            console.error('Error adding MAC address:', error);
            return {
                success: false,
                message: `Error adding MAC address: ${error.message}`
            };
        }
    }
    
    async updateMACAccess(macAddress, accessType) {
        try {
            const normalizedMac = macAddress.toLowerCase();
            const data = await this.readDatabase();
            
            if (!data.macAddresses[normalizedMac]) {
                return {
                    success: false,
                    message: 'MAC address not found in whitelist'
                };
            }
            
            data.macAddresses[normalizedMac].accessType = accessType;
            data.macAddresses[normalizedMac].updatedAt = new Date().toISOString();
            
            const success = await this.writeDatabase(data);
            
            if (success) {
                return {
                    success: true,
                    message: 'Access type updated successfully',
                    data: data.macAddresses[normalizedMac]
                };
            } else {
                return {
                    success: false,
                    message: 'Failed to save to database'
                };
            }
            
        } catch (error) {
            console.error('Error updating MAC access:', error);
            return {
                success: false,
                message: `Error updating MAC access: ${error.message}`
            };
        }
    }
    
    async removeMACAddress(macAddress) {
        try {
            const normalizedMac = macAddress.toLowerCase();
            const data = await this.readDatabase();
            
            if (!data.macAddresses[normalizedMac]) {
                return {
                    success: false,
                    message: 'MAC address not found in whitelist'
                };
            }
            
            delete data.macAddresses[normalizedMac];
            
            const success = await this.writeDatabase(data);
            
            if (success) {
                return {
                    success: true,
                    message: 'MAC address removed successfully'
                };
            } else {
                return {
                    success: false,
                    message: 'Failed to save to database'
                };
            }
            
        } catch (error) {
            console.error('Error removing MAC address:', error);
            return {
                success: false,
                message: `Error removing MAC address: ${error.message}`
            };
        }
    }
    
    async listMACAddresses() {
        try {
            const data = await this.readDatabase();
            const now = new Date();
            const day24h = 24 * 60 * 60 * 1000;
            const day7d = 7 * day24h;
            
            const macList = Object.entries(data.macAddresses).map(([mac, entry]) => {
                return {
                    macAddress: mac,
                    description: entry.description,
                    accessType: entry.accessType || 'trial',
                    addedAt: entry.addedAt,
                    lastSeen: entry.lastSeen,
                    accessCount: entry.accessCount || 0,
                    lastDevice: entry.lastDevice,
                    id: entry.id
                };
            });
            
            const statistics = {
                total: macList.length,
                activeLast24h: macList.filter(entry => {
                    if (!entry.lastSeen) return false;
                    const lastSeen = new Date(entry.lastSeen);
                    return (now - lastSeen) <= day24h;
                }).length,
                activeLast7d: macList.filter(entry => {
                    if (!entry.lastSeen) return false;
                    const lastSeen = new Date(entry.lastSeen);
                    return (now - lastSeen) <= day7d;
                }).length,
                neverUsed: macList.filter(entry => !entry.lastSeen).length,
                totalAccesses: data.statistics.totalAccesses || 0
            };
            
            return {
                success: true,
                message: 'MAC addresses retrieved successfully',
                data: {
                    macAddresses: macList,
                    statistics: statistics
                }
            };
            
        } catch (error) {
            console.error('Error listing MAC addresses:', error);
            return {
                success: false,
                message: `Error retrieving MAC addresses: ${error.message}`,
                data: null
            };
        }
    }
    
    async bulkAddMACs(macAddressList) {
        try {
            const data = await this.readDatabase();
            const results = [];
            let addedCount = 0;
            let skippedCount = 0;
            
            for (const macEntry of macAddressList) {
                const normalizedMac = macEntry.macAddress.toLowerCase();
                
                if (data.macAddresses[normalizedMac]) {
                    results.push({
                        macAddress: normalizedMac,
                        status: 'skipped',
                        reason: 'Already exists'
                    });
                    skippedCount++;
                } else {
                    data.macAddresses[normalizedMac] = {
                        description: macEntry.description || 'Bulk added device',
                        accessType: macEntry.accessType || 'trial',
                        addedAt: new Date().toISOString(),
                        lastSeen: null,
                        accessCount: 0,
                        lastDevice: null,
                        id: crypto.randomUUID()
                    };
                    
                    results.push({
                        macAddress: normalizedMac,
                        status: 'added',
                        accessType: macEntry.accessType || 'trial'
                    });
                    addedCount++;
                }
            }
            
            const success = await this.writeDatabase(data);
            
            if (success) {
                return {
                    success: true,
                    message: `Bulk operation completed: ${addedCount} added, ${skippedCount} skipped`,
                    data: {
                        results: results,
                        summary: {
                            total: macAddressList.length,
                            added: addedCount,
                            skipped: skippedCount
                        }
                    }
                };
            } else {
                return {
                    success: false,
                    message: 'Failed to save bulk changes to database'
                };
            }
            
        } catch (error) {
            console.error('Error in bulk add operation:', error);
            return {
                success: false,
                message: `Bulk add error: ${error.message}`
            };
        }
    }
}

export default MACDatabase;
