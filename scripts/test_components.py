#!/usr/bin/env python3
"""
AMOSKYS Component Testing Script
Tests each component individually before full integration

Usage:
    python scripts/test_components.py --all
    python scripts/test_components.py --snmp
    python scripts/test_components.py --proc
    python scripts/test_components.py --correlation
"""

import asyncio
import sys
import argparse
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ComponentTest")


class ComponentTester:
    """Test individual components"""
    
    def __init__(self):
        self.results = {}
        
    async def test_snmp_config(self):
        """Test SNMP configuration loading"""
        logger.info("\n" + "="*60)
        logger.info("TEST 1: SNMP Configuration")
        logger.info("="*60)
        
        try:
            from amoskys.agents.snmp.enhanced_collector import SNMPMetricsConfig
            
            config_path = project_root / "config" / "snmp_metrics_config.yaml"
            config = SNMPMetricsConfig(str(config_path))
            
            # Test profile application
            for profile in ['minimal', 'standard', 'full']:
                config.apply_profile(profile)
                enabled, total = config.get_metric_count()
                logger.info(f"  Profile '{profile}': {enabled}/{total} metrics enabled")
            
            # List categories
            categories = config.list_categories()
            logger.info(f"  Available categories: {categories}")
            
            self.results['snmp_config'] = 'PASS'
            logger.info("✓ SNMP Configuration: PASS")
            return True
            
        except Exception as e:
            logger.error(f"✗ SNMP Configuration: FAIL - {e}")
            self.results['snmp_config'] = f'FAIL: {e}'
            return False
            
    async def test_snmp_collection(self):
        """Test SNMP data collection"""
        logger.info("\n" + "="*60)
        logger.info("TEST 2: SNMP Collection")
        logger.info("="*60)
        
        try:
            from amoskys.agents.snmp.enhanced_collector import SNMPMetricsConfig, EnhancedSNMPCollector
            
            config_path = project_root / "config" / "snmp_metrics_config.yaml"
            config = SNMPMetricsConfig(str(config_path))
            config.apply_profile('minimal')  # Use minimal for testing
            
            collector = EnhancedSNMPCollector(config)
            
            logger.info("  Configuration loaded successfully")
            logger.info("  Enhanced SNMP Collector created")
            logger.info("  ⚠️  SNMP collection test skipped (requires snmpd)")
            logger.info("  To enable: sudo launchctl load -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist")
            
            # Just verify the collector is properly configured
            enabled, total = config.get_metric_count()
            logger.info(f"  Collector configured for {enabled}/{total} metrics")
            
            self.results['snmp_collection'] = 'PASS (config only)'
            logger.info("✓ SNMP Collection: PASS (configuration verified)")
            return True
                
        except Exception as e:
            logger.error(f"✗ SNMP Collection: FAIL - {e}")
            self.results['snmp_collection'] = f'FAIL: {e}'
            return False
            
    async def test_proc_agent(self):
        """Test process monitoring agent"""
        logger.info("\n" + "="*60)
        logger.info("TEST 3: Process Agent")
        logger.info("="*60)
        
        try:
            # Use simplified version that doesn't need protobuf
            from amoskys.agents.proc.proc_agent_simple import ProcAgent
            
            agent = ProcAgent(collection_interval=30)
            
            logger.info("  Scanning processes...")
            data = await agent.collect_once()
            
            if data:
                logger.info(f"  Process count: {data.get('process_count', 0)}")
                logger.info(f"  New processes: {data.get('new_processes', 0)}")
                logger.info(f"  Suspicious: {data.get('suspicious_processes', 0)}")
                
                # Show top CPU
                top_cpu = data.get('top_cpu', [])
                if top_cpu:
                    logger.info("  Top 3 CPU consumers:")
                    for i, proc in enumerate(top_cpu[:3], 1):
                        logger.info(f"    {i}. {proc['name']} - {proc['cpu_percent']:.1f}%")
                
                self.results['proc_agent'] = 'PASS'
                logger.info("✓ Process Agent: PASS")
                return True
            else:
                self.results['proc_agent'] = 'FAIL: No data returned'
                logger.error("✗ Process Agent: FAIL")
                return False
                
        except Exception as e:
            logger.error(f"✗ Process Agent: FAIL - {e}")
            self.results['proc_agent'] = f'FAIL: {e}'
            return False
            
    async def test_score_junction(self):
        """Test correlation engine"""
        logger.info("\n" + "="*60)
        logger.info("TEST 4: ScoreJunction Correlation")
        logger.info("="*60)
        
        try:
            from amoskys.intelligence.score_junction import ScoreJunction, ThreatLevel
            
            junction = ScoreJunction()
            
            logger.info(f"  Created ScoreJunction with {junction.correlation_window}s window")
            logger.info(f"  Loaded {len(junction.correlation_engine.rules)} correlation rules")
            logger.info(f"  Correlation rules: {[r['name'] for r in junction.correlation_engine.rules]}")
            
            # Get statistics
            stats = junction.get_statistics()
            logger.info(f"  Statistics: {stats['events_processed']} events, {stats.get('correlations_found', 0)} correlations")
            
            self.results['score_junction'] = 'PASS'
            logger.info("✓ ScoreJunction: PASS")
            return True
            
        except Exception as e:
            logger.error(f"✗ ScoreJunction: FAIL - {e}")
            import traceback
            traceback.print_exc()
            self.results['score_junction'] = f'FAIL: {e}'
            return False
            
    async def test_eventbus_connection(self):
        """Test connection to EventBus"""
        logger.info("\n" + "="*60)
        logger.info("TEST 5: EventBus Connection")
        logger.info("="*60)
        
        try:
            import grpc
            
            logger.info("  Attempting to connect to localhost:50051...")
            
            channel = grpc.aio.insecure_channel('localhost:50051')
            
            # Test connection (with timeout)
            try:
                await asyncio.wait_for(channel.channel_ready(), timeout=2.0)
                await channel.close()
                
                self.results['eventbus'] = 'PASS'
                logger.info("✓ EventBus Connection: PASS")
                return True
            except asyncio.TimeoutError:
                await channel.close()
                logger.warning("✗ EventBus Connection: FAIL - Timeout (not running)")
                logger.warning("  EventBus may not be running. Start it with:")
                logger.warning("    python -m amoskys.eventbus.server")
                self.results['eventbus'] = 'FAIL: Not running'
                return False
            
        except Exception as e:
            logger.error(f"✗ EventBus Connection: FAIL - {e}")
            self.results['eventbus'] = f'FAIL: {e}'
            return False
            
    async def test_wal_database(self):
        """Test WAL database"""
        logger.info("\n" + "="*60)
        logger.info("TEST 6: WAL Database")
        logger.info("="*60)
        
        try:
            import sqlite3
            
            wal_path = project_root / "data" / "wal" / "flowagent.db"
            
            if not wal_path.exists():
                logger.warning("✗ WAL Database: FAIL - Database file not found")
                logger.warning(f"  Expected location: {wal_path}")
                self.results['wal_database'] = 'FAIL: Not found'
                return False
                
            conn = sqlite3.connect(str(wal_path))
            cursor = conn.cursor()
            
            # Check table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wal'")
            if not cursor.fetchone():
                logger.error("✗ WAL Database: FAIL - 'wal' table not found")
                self.results['wal_database'] = 'FAIL: No wal table'
                return False
                
            # Get event count
            cursor.execute("SELECT COUNT(*) FROM wal")
            count = cursor.fetchone()[0]
            
            # Get size
            cursor.execute("SELECT SUM(LENGTH(bytes)) FROM wal")
            size_bytes = cursor.fetchone()[0] or 0
            
            logger.info(f"  Total events: {count}")
            logger.info(f"  Total size: {size_bytes:,} bytes")
            
            # Get recent event
            cursor.execute("SELECT id, idem, ts_ns FROM wal ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                logger.info(f"  Latest event: id={row[0]}, idem={row[1][:20]}...")
                
            conn.close()
            
            self.results['wal_database'] = 'PASS'
            logger.info("✓ WAL Database: PASS")
            return True
            
        except Exception as e:
            logger.error(f"✗ WAL Database: FAIL - {e}")
            self.results['wal_database'] = f'FAIL: {e}'
            return False
            
    def print_summary(self):
        """Print test summary"""
        logger.info("\n" + "="*60)
        logger.info("TEST SUMMARY")
        logger.info("="*60)
        
        passed = sum(1 for r in self.results.values() if r == 'PASS')
        total = len(self.results)
        
        for test, result in self.results.items():
            status = "✓" if result == "PASS" else "✗"
            logger.info(f"{status} {test}: {result}")
            
        logger.info(f"\nTotal: {passed}/{total} tests passed")
        
        if passed == total:
            logger.info("\n🎉 All tests passed! System is ready.")
            logger.info("\nNext steps:")
            logger.info("  1. python scripts/activate_multiagent.py")
            logger.info("  2. Open dashboard at http://localhost:5000")
        else:
            logger.warning("\n⚠️  Some tests failed. Check errors above.")
            
    async def run_all(self):
        """Run all tests"""
        logger.info("""
╔═══════════════════════════════════════════════════════════╗
║           AMOSKYS Component Test Suite                   ║
╚═══════════════════════════════════════════════════════════╝
        """)
        
        await self.test_snmp_config()
        await self.test_snmp_collection()
        await self.test_proc_agent()
        await self.test_score_junction()
        await self.test_eventbus_connection()
        await self.test_wal_database()
        
        self.print_summary()


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Test AMOSKYS components')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    parser.add_argument('--snmp', action='store_true', help='Test SNMP only')
    parser.add_argument('--proc', action='store_true', help='Test ProcAgent only')
    parser.add_argument('--correlation', action='store_true', help='Test ScoreJunction only')
    parser.add_argument('--eventbus', action='store_true', help='Test EventBus connection only')
    parser.add_argument('--wal', action='store_true', help='Test WAL database only')
    
    args = parser.parse_args()
    
    tester = ComponentTester()
    
    if args.all or not any([args.snmp, args.proc, args.correlation, args.eventbus, args.wal]):
        await tester.run_all()
    else:
        if args.snmp:
            await tester.test_snmp_config()
            await tester.test_snmp_collection()
        if args.proc:
            await tester.test_proc_agent()
        if args.correlation:
            await tester.test_score_junction()
        if args.eventbus:
            await tester.test_eventbus_connection()
        if args.wal:
            await tester.test_wal_database()
            
        tester.print_summary()


if __name__ == '__main__':
    asyncio.run(main())
