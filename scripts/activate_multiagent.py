#!/usr/bin/env python3
"""
AMOSKYS Multi-Agent System Activation Script
Brings together SNMP Enhanced Collector, ProcAgent, and ScoreJunction

This script:
1. Loads enhanced SNMP configuration
2. Starts ProcAgent for process monitoring
3. Starts ScoreJunction for correlation
4. Integrates all agents with EventBus
"""

import asyncio
import logging
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from amoskys.agents.snmp.enhanced_collector import SNMPMetricsConfig, EnhancedSNMPCollector
from amoskys.agents.proc.proc_agent import ProcAgent
from amoskys.intelligence.score_junction import ScoreJunction
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

import grpc

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("MultiAgent")


class MultiAgentOrchestrator:
    """Coordinates multiple agents and sends telemetry to EventBus"""
    
    def __init__(self, eventbus_addr: str = "localhost:50051"):
        self.eventbus_addr = eventbus_addr
        self.snmp_config = None
        self.snmp_collector = None
        self.proc_agent = None
        self.score_junction = None
        self.running = False
        
    async def initialize(self):
        """Initialize all agents"""
        logger.info("Initializing multi-agent system...")
        
        # 1. Load SNMP configuration
        config_path = project_root / "config" / "snmp_metrics_config.yaml"
        if not config_path.exists():
            logger.error(f"SNMP config not found: {config_path}")
            return False
            
        self.snmp_config = SNMPMetricsConfig(str(config_path))
        
        # Apply 'standard' profile (can be changed to 'full' for more metrics)
        self.snmp_config.apply_profile('standard')
        
        enabled, total = self.snmp_config.get_metric_count()
        logger.info(f"SNMP: Enabled {enabled}/{total} metrics")
        logger.info(f"SNMP Categories: {self.snmp_config.list_categories()}")
        
        # 2. Create SNMP collector
        self.snmp_collector = EnhancedSNMPCollector(self.snmp_config)
        
        # 3. Create ProcAgent
        self.proc_agent = ProcAgent(
            collection_interval=30,  # 30 seconds
            suspicious_patterns=['malware', 'cryptominer', 'backdoor']
        )
        
        # 4. Create ScoreJunction
        self.score_junction = ScoreJunction(
            config={
                'correlation_window_seconds': 300,  # 5 minutes
                'min_confidence': 0.3
            }
        )
        
        logger.info("✓ All agents initialized")
        return True
        
    async def connect_to_eventbus(self):
        """Establish gRPC connection to EventBus"""
        try:
            self.channel = grpc.aio.insecure_channel(self.eventbus_addr)
            from amoskys.proto import eventbus_pb2_grpc
            self.eventbus_stub = eventbus_pb2_grpc.EventBusStub(self.channel)
            
            # Test connection
            await self.channel.channel_ready()
            logger.info(f"✓ Connected to EventBus at {self.eventbus_addr}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to EventBus: {e}")
            return False
            
    async def send_telemetry(self, envelope: telemetry_pb2.UniversalEnvelope):
        """Send telemetry envelope to EventBus"""
        try:
            from amoskys.proto import eventbus_pb2
            
            # Create PublishRequest
            request = eventbus_pb2.PublishRequest(
                idempotency_key=envelope.idempotency_key,
                data=envelope.SerializeToString()
            )
            
            response = await self.eventbus_stub.Publish(request)
            
            if response.status != eventbus_pb2.PublishResponse.Status.OK:
                logger.warning(f"EventBus returned status: {response.status}")
                
        except Exception as e:
            logger.error(f"Failed to send telemetry: {e}")
            
    async def collect_snmp_metrics(self):
        """Collect SNMP metrics and send to EventBus"""
        try:
            # Collect from localhost
            results = await self.snmp_collector.collect_all('localhost', 'public')
            
            logger.info(f"SNMP: Collected {len(results)} metrics")
            
            # Create telemetry envelope (simplified for now)
            envelope = telemetry_pb2.UniversalEnvelope()
            envelope.agent_id = "snmp-enhanced-001"
            envelope.timestamp_ns = int(asyncio.get_event_loop().time() * 1e9)
            envelope.idempotency_key = f"snmp-{envelope.timestamp_ns}"
            
            # Send to EventBus
            await self.send_telemetry(envelope)
            
            # Send to ScoreJunction for correlation
            threat_score = await self.score_junction.process_telemetry(envelope)
            
            if threat_score.threat_level != "BENIGN":
                logger.warning(
                    f"⚠ Threat detected: {threat_score.threat_level} "
                    f"(score: {threat_score.score:.2f}, "
                    f"confidence: {threat_score.confidence:.2f})"
                )
                
        except Exception as e:
            logger.error(f"SNMP collection error: {e}")
            
    async def collect_process_metrics(self):
        """Collect process metrics and send to EventBus"""
        try:
            # Get process telemetry
            envelopes = await self.proc_agent.collect_once()
            
            logger.info(f"ProcAgent: Generated {len(envelopes)} telemetry events")
            
            for envelope in envelopes:
                # Send to EventBus
                await self.send_telemetry(envelope)
                
                # Send to ScoreJunction for correlation
                threat_score = await self.score_junction.process_telemetry(envelope)
                
                if threat_score.threat_level != "BENIGN":
                    logger.warning(
                        f"⚠ Process threat detected: {threat_score.threat_level} "
                        f"(score: {threat_score.score:.2f})"
                    )
                    
        except Exception as e:
            logger.error(f"Process collection error: {e}")
            
    async def collection_loop(self):
        """Main collection loop for all agents"""
        self.running = True
        iteration = 0
        
        logger.info("Starting collection loop...")
        
        while self.running:
            iteration += 1
            logger.info(f"\n{'='*60}")
            logger.info(f"Collection Iteration #{iteration}")
            logger.info(f"{'='*60}")
            
            # Collect from all agents
            await asyncio.gather(
                self.collect_snmp_metrics(),
                self.collect_process_metrics()
            )
            
            # Show correlation stats
            stats = self.score_junction.get_statistics()
            logger.info(
                f"ScoreJunction: {stats['total_events']} events, "
                f"{stats['total_threats']} threats detected"
            )
            
            # Wait before next iteration
            await asyncio.sleep(30)  # 30-second interval
            
    async def run(self):
        """Main entry point"""
        logger.info("""
╔═══════════════════════════════════════════════════════════╗
║      AMOSKYS Multi-Agent Telemetry System v2.0           ║
║                Agent Harmony Architecture                 ║
╚═══════════════════════════════════════════════════════════╝
        """)
        
        # Initialize all components
        if not await self.initialize():
            logger.error("Initialization failed")
            return
            
        # Connect to EventBus
        if not await self.connect_to_eventbus():
            logger.error("EventBus connection failed")
            return
            
        # Start collection loop
        try:
            await self.collection_loop()
        except KeyboardInterrupt:
            logger.info("\n\nShutting down gracefully...")
            self.running = False
            
    async def shutdown(self):
        """Clean shutdown"""
        self.running = False
        if hasattr(self, 'channel'):
            await self.channel.close()


async def main():
    """Main entry point"""
    orchestrator = MultiAgentOrchestrator()
    
    try:
        await orchestrator.run()
    except KeyboardInterrupt:
        pass
    finally:
        await orchestrator.shutdown()


if __name__ == '__main__':
    asyncio.run(main())
