#!/usr/bin/env node
// migrate-data.js - Migration script for existing MAC address data
// Run this locally to prepare your data before deployment

import fs from 'fs/promises';
import path from 'path';

const DATA_DIR = './data';
const DATA_FILE = path.join(DATA_DIR, 'mac-whitelist.json');

// Sample MAC addresses - replace with your actual data
const SAMPLE_DATA = [
    {
        macAddress: 'aa:bb:cc:dd:ee:ff',
        description: 'John\'s MacBook Pro',
        accessType: 'unlimited',
        addedAt: '2024-01-01T00:00:00.000Z',
        lastSeen: null,
        accessCount: 0,
        lastDevice: null
    },
    {
        macAddress: '11:22:33:44:55:66', 
        description: 'Admin Laptop',
        accessType: 'admin',
        addedAt: '2024-01-01T00:00:00.000Z',
        lastSeen: null,
        accessCount: 0,
        lastDevice: null
    }
];

async function createInitialData() {
    console.log('🔄 Creating initial MAC whitelist data...');
    
    try {
        // Create data directory
        await fs.mkdir(DATA_DIR, { recursive: true });
        console.log('📁 Data directory created');
        
        // Create initial data structure
        const initialData = {
            macAddresses: [], // Start empty - add your MACs via admin panel
            statistics: {
                total: 0,
                activeLast24h: 0,
                activeLast7d: 0,
                neverUsed: 0,
                totalAccesses: 0
            },
            lastUpdated: new Date().toISOString(),
            version: '2.0'
        };
        
        // Write to file
        await fs.writeFile(DATA_FILE, JSON.stringify(initialData, null, 2));
        console.log('✅ Initial data file created:', DATA_FILE);
        
        console.log('\n📋 Next Steps:');
        console.log('1. Commit and push this data file to your repository');
        console.log('2. Deploy to Vercel'); 
        console.log('3. Set ADMIN_SECRET_KEY environment variable in Vercel');
        console.log('4. Use admin mode to add your MAC addresses:');
        console.log('   node sat-launcher-mac.js admin');
        
    } catch (error) {
        console.error('❌ Error creating initial data:', error);
    }
}

async function addSampleData() {
    console.log('🔄 Adding sample MAC addresses...');
    
    try {
        const data = {
            macAddresses: SAMPLE_DATA,
            statistics: {
                total: SAMPLE_DATA.length,
                activeLast24h: 0,
                activeLast7d: 0,
                neverUsed: SAMPLE_DATA.length,
                totalAccesses: 0
            },
            lastUpdated: new Date().toISOString(),
            version: '2.0'
        };
        
        await fs.mkdir(DATA_DIR, { recursive: true });
        await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2));
        
        console.log('✅ Sample data added with MAC addresses:');
        SAMPLE_DATA.forEach(entry => {
            console.log(`   ${entry.macAddress} - ${entry.description} (${entry.accessType})`);
        });
        
        console.log('\n⚠️  IMPORTANT: Replace sample data with your actual MAC addresses!');
        
    } catch (error) {
        console.error('❌ Error adding sample data:', error);
    }
}

// Command line interface
const command = process.argv[2];

switch (command) {
    case 'init':
    case 'create':
        await createInitialData();
        break;
    case 'sample':
        await addSampleData();
        break;
    default:
        console.log('🛠️  MAC Address Data Migration Script');
        console.log('=====================================');
        console.log('');
        console.log('Usage:');
        console.log('  node migrate-data.js init     - Create empty data file');
        console.log('  node migrate-data.js sample   - Create with sample MAC addresses');
        console.log('');
        console.log('Recommended: Use "init" and add your MACs via admin panel');
        break;
}
