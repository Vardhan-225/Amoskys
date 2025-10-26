"""
AMOSKYS Edge Optimization Engine
Resource-constrained deployment for microprocessor agents
"""

import asyncio
import logging
import psutil
import json
import gzip
import lz4.frame
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading
from collections import deque
from pathlib import Path
import queue
import time

logger = logging.getLogger(__name__)

@dataclass
class ResourceConstraints:
    """Resource constraints for edge deployment"""
    max_cpu_percent: float = 50.0      # Maximum CPU usage
    max_memory_mb: int = 256            # Maximum memory in MB
    max_storage_mb: int = 1024          # Maximum storage in MB
    max_bandwidth_kbps: int = 100       # Maximum bandwidth in KB/s
    max_concurrent_connections: int = 10 # Maximum concurrent network connections
    max_queue_size: int = 1000          # Maximum event queue size
    max_batch_age_seconds: int = 30     # Maximum time to hold events before sending

@dataclass
class EdgeMetrics:
    """Real-time edge performance metrics"""
    cpu_usage_percent: float
    memory_usage_mb: float
    storage_usage_mb: float
    network_usage_kbps: float
    queue_depth: int
    events_processed: int
    events_dropped: int
    compression_ratio: float
    uptime_seconds: float
    last_update: datetime

class CompressionEngine:
    """Intelligent compression for telemetry data"""
    
    def __init__(self):
        self.algorithms = {
            'gzip': {'compress': self._gzip_compress, 'decompress': self._gzip_decompress},
            'lz4': {'compress': self._lz4_compress, 'decompress': self._lz4_decompress},
            'none': {'compress': self._no_compression, 'decompress': self._no_decompression}
        }
        self.stats = {
            'total_compressed': 0,
            'total_original_bytes': 0,
            'total_compressed_bytes': 0,
            'compression_time_ms': 0,
            'algorithm_performance': {}
        }
        
    def compress_data(self, data: bytes, algorithm: str = 'auto') -> Tuple[bytes, str, float]:
        """Compress data with optimal algorithm selection"""
        if algorithm == 'auto':
            algorithm = self._select_optimal_algorithm(data)
            
        start_time = time.time()
        compressed_data = self.algorithms[algorithm]['compress'](data)
        compression_time = (time.time() - start_time) * 1000
        
        ratio = len(compressed_data) / len(data) if len(data) > 0 else 1.0
        
        # Update statistics
        self.stats['total_compressed'] += 1
        self.stats['total_original_bytes'] += len(data)
        self.stats['total_compressed_bytes'] += len(compressed_data)
        self.stats['compression_time_ms'] += compression_time
        
        if algorithm not in self.stats['algorithm_performance']:
            self.stats['algorithm_performance'][algorithm] = {
                'count': 0, 'total_ratio': 0.0, 'total_time_ms': 0.0
            }
        
        alg_stats = self.stats['algorithm_performance'][algorithm]
        alg_stats['count'] += 1
        alg_stats['total_ratio'] += ratio
        alg_stats['total_time_ms'] += compression_time
        
        return compressed_data, algorithm, ratio
        
    def _select_optimal_algorithm(self, data: bytes) -> str:
        """Select optimal compression algorithm based on data characteristics"""
        data_size = len(data)
        
        # For small data, compression overhead might not be worth it
        if data_size < 100:
            return 'none'
        
        # For medium data, use fast compression
        if data_size < 10000:
            return 'lz4'
            
        # For large data, use better compression ratio
        return 'gzip'
        
    def _gzip_compress(self, data: bytes) -> bytes:
        return gzip.compress(data, compresslevel=6)
        
    def _gzip_decompress(self, data: bytes) -> bytes:
        return gzip.decompress(data)
        
    def _lz4_compress(self, data: bytes) -> bytes:
        return lz4.frame.compress(data)
        
    def _lz4_decompress(self, data: bytes) -> bytes:
        return lz4.frame.decompress(data)
        
    def _no_compression(self, data: bytes) -> bytes:
        return data
        
    def _no_decompression(self, data: bytes) -> bytes:
        return data
        
    def get_compression_stats(self) -> Dict:
        """Get compression performance statistics"""
        overall_ratio = (self.stats['total_compressed_bytes'] / 
                        self.stats['total_original_bytes'] 
                        if self.stats['total_original_bytes'] > 0 else 1.0)
        
        avg_time = (self.stats['compression_time_ms'] / 
                   self.stats['total_compressed'] 
                   if self.stats['total_compressed'] > 0 else 0.0)
        
        return {
            'overall_compression_ratio': overall_ratio,
            'average_compression_time_ms': avg_time,
            'total_bytes_saved': self.stats['total_original_bytes'] - self.stats['total_compressed_bytes'],
            'algorithm_performance': self.stats['algorithm_performance']
        }

class EdgeEventBuffer:
    """Intelligent event buffering for edge devices"""
    
    def __init__(self, constraints: ResourceConstraints):
        self.constraints = constraints
        self.buffer = deque(maxlen=constraints.max_queue_size)
        self.lock = threading.Lock()
        self.total_events = 0
        self.dropped_events = 0
        self.last_flush = datetime.now()
        
    def add_event(self, event: Dict) -> bool:
        """Add event to buffer with overflow protection"""
        with self.lock:
            if len(self.buffer) >= self.constraints.max_queue_size:
                # Drop oldest event to make room
                dropped = self.buffer.popleft()
                self.dropped_events += 1
                logger.warning(f"Dropped event due to buffer overflow: {dropped.get('event_id', 'unknown')}")
            
            # Add timestamp and buffer metadata
            event['buffered_at'] = datetime.now().isoformat()
            event['buffer_sequence'] = self.total_events
            
            self.buffer.append(event)
            self.total_events += 1
            
            return True
            
    def get_batch(self, max_size: int = None) -> List[Dict]:
        """Get a batch of events for transmission"""
        if max_size is None:
            max_size = min(100, len(self.buffer))
            
        with self.lock:
            batch = []
            for _ in range(min(max_size, len(self.buffer))):
                if self.buffer:
                    batch.append(self.buffer.popleft())
                    
            if batch:
                self.last_flush = datetime.now()
                
            return batch
            
    def should_flush(self) -> bool:
        """Determine if buffer should be flushed"""
        with self.lock:
            # Flush if buffer is getting full
            if len(self.buffer) >= self.constraints.max_queue_size * 0.8:
                return True
                
            # Flush if events are getting old
            time_since_flush = datetime.now() - self.last_flush
            if time_since_flush.total_seconds() >= self.constraints.max_batch_age_seconds:
                return True
                
            # Flush if we have a minimum batch
            if len(self.buffer) >= 10:
                return True
                
            return False
            
    def get_stats(self) -> Dict:
        """Get buffer statistics"""
        with self.lock:
            return {
                'current_size': len(self.buffer),
                'max_size': self.constraints.max_queue_size,
                'total_events': self.total_events,
                'dropped_events': self.dropped_events,
                'fill_percentage': (len(self.buffer) / self.constraints.max_queue_size) * 100,
                'last_flush': self.last_flush.isoformat()
            }

class ResourceMonitor:
    """Real-time resource monitoring for edge devices"""
    
    def __init__(self, constraints: ResourceConstraints):
        self.constraints = constraints
        self.metrics_history = deque(maxlen=100)  # Keep last 100 measurements
        self.alerts = []
        self.start_time = datetime.now()
        
    def collect_metrics(self) -> EdgeMetrics:
        """Collect current system metrics"""
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_usage_mb = (memory.used / 1024 / 1024)
        
        # Disk usage (current directory)
        disk = psutil.disk_usage('.')
        storage_usage_mb = (disk.used / 1024 / 1024)
        
        # Network usage (approximated)
        network_io = psutil.net_io_counters()
        network_usage_kbps = 0  # Would need to calculate rate
        
        # Calculate uptime
        uptime = (datetime.now() - self.start_time).total_seconds()
        
        metrics = EdgeMetrics(
            cpu_usage_percent=cpu_percent,
            memory_usage_mb=memory_usage_mb,
            storage_usage_mb=storage_usage_mb,
            network_usage_kbps=network_usage_kbps,
            queue_depth=0,  # Will be set by caller
            events_processed=0,  # Will be set by caller
            events_dropped=0,  # Will be set by caller
            compression_ratio=1.0,  # Will be set by caller
            uptime_seconds=uptime,
            last_update=datetime.now()
        )
        
        # Store in history
        self.metrics_history.append(metrics)
        
        # Check for constraint violations
        self._check_constraints(metrics)
        
        return metrics
        
    def _check_constraints(self, metrics: EdgeMetrics):
        """Check if metrics violate resource constraints"""
        violations = []
        
        if metrics.cpu_usage_percent > self.constraints.max_cpu_percent:
            violations.append(f"CPU usage {metrics.cpu_usage_percent:.1f}% exceeds limit {self.constraints.max_cpu_percent}%")
            
        if metrics.memory_usage_mb > self.constraints.max_memory_mb:
            violations.append(f"Memory usage {metrics.memory_usage_mb:.1f}MB exceeds limit {self.constraints.max_memory_mb}MB")
            
        if metrics.storage_usage_mb > self.constraints.max_storage_mb:
            violations.append(f"Storage usage {metrics.storage_usage_mb:.1f}MB exceeds limit {self.constraints.max_storage_mb}MB")
            
        if violations:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'type': 'RESOURCE_CONSTRAINT_VIOLATION',
                'violations': violations,
                'current_metrics': asdict(metrics)
            }
            self.alerts.append(alert)
            logger.warning(f"Resource constraint violations: {violations}")
            
    def is_resource_available(self, resource_type: str, required_amount: float) -> bool:
        """Check if sufficient resources are available"""
        if not self.metrics_history:
            return True
            
        latest = self.metrics_history[-1]
        
        if resource_type == 'cpu':
            available = self.constraints.max_cpu_percent - latest.cpu_usage_percent
            return available >= required_amount
            
        elif resource_type == 'memory':
            available = self.constraints.max_memory_mb - latest.memory_usage_mb
            return available >= required_amount
            
        elif resource_type == 'storage':
            available = self.constraints.max_storage_mb - latest.storage_usage_mb
            return available >= required_amount
            
        return True
        
    def get_resource_recommendation(self) -> Dict:
        """Get recommendations for resource optimization"""
        if len(self.metrics_history) < 10:
            return {'status': 'insufficient_data'}
            
        # Calculate averages over recent history
        recent_metrics = list(self.metrics_history)[-10:]
        avg_cpu = sum(m.cpu_usage_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_usage_mb for m in recent_metrics) / len(recent_metrics)
        
        recommendations = []
        
        if avg_cpu > self.constraints.max_cpu_percent * 0.8:
            recommendations.append({
                'type': 'CPU_HIGH',
                'message': 'Consider reducing collection frequency or enabling more aggressive filtering',
                'suggested_action': 'increase_batch_size'
            })
            
        if avg_memory > self.constraints.max_memory_mb * 0.8:
            recommendations.append({
                'type': 'MEMORY_HIGH',
                'message': 'Consider reducing buffer size or increasing compression',
                'suggested_action': 'reduce_buffer_size'
            })
            
        return {
            'status': 'ok',
            'average_cpu': avg_cpu,
            'average_memory': avg_memory,
            'recommendations': recommendations
        }

class EdgeOptimizer:
    """Main edge optimization coordinator"""
    
    def __init__(self, constraints: ResourceConstraints):
        self.constraints = constraints
        self.compression_engine = CompressionEngine()
        self.event_buffer = EdgeEventBuffer(constraints)
        self.resource_monitor = ResourceMonitor(constraints)
        
        self.optimization_enabled = True
        self.adaptive_mode = True
        self.performance_stats = {
            'optimization_cycles': 0,
            'bandwidth_saved_bytes': 0,
            'cpu_saved_percent': 0,
            'memory_saved_mb': 0
        }
        
    async def start_optimization_loop(self):
        """Start the main optimization loop"""
        logger.info("Starting edge optimization loop")
        
        while self.optimization_enabled:
            try:
                # Collect current metrics
                metrics = self.resource_monitor.collect_metrics()
                
                # Update metrics with buffer stats
                buffer_stats = self.event_buffer.get_stats()
                metrics.queue_depth = buffer_stats['current_size']
                metrics.events_dropped = buffer_stats['dropped_events']
                
                # Apply optimizations if needed
                if self.adaptive_mode:
                    await self._apply_adaptive_optimizations(metrics)
                
                # Log performance periodically
                if self.performance_stats['optimization_cycles'] % 60 == 0:
                    self._log_performance_summary(metrics)
                
                self.performance_stats['optimization_cycles'] += 1
                
                # Wait before next cycle
                await asyncio.sleep(1.0)  # 1 second optimization cycle
                
            except Exception as e:
                logger.error(f"Optimization loop error: {e}")
                await asyncio.sleep(5.0)  # Error recovery delay
                
    async def _apply_adaptive_optimizations(self, metrics: EdgeMetrics):
        """Apply adaptive optimizations based on current metrics"""
        optimizations_applied = []
        
        # CPU optimization
        if metrics.cpu_usage_percent > self.constraints.max_cpu_percent * 0.9:
            # Reduce processing frequency
            await self._reduce_processing_load()
            optimizations_applied.append('reduced_processing_load')
            
        # Memory optimization
        if metrics.memory_usage_mb > self.constraints.max_memory_mb * 0.9:
            # Force buffer flush
            await self._emergency_buffer_flush()
            optimizations_applied.append('emergency_buffer_flush')
            
        # Network optimization
        if metrics.network_usage_kbps > self.constraints.max_bandwidth_kbps * 0.8:
            # Increase compression aggressiveness
            await self._increase_compression()
            optimizations_applied.append('increased_compression')
            
        if optimizations_applied:
            logger.info(f"Applied optimizations: {optimizations_applied}")
            
    async def _reduce_processing_load(self):
        """Reduce processing load by adjusting collection parameters"""
        # This would integrate with the collection manager to:
        # - Increase batch sizes
        # - Reduce collection frequency
        # - Enable more aggressive filtering
        logger.info("Reducing processing load to save CPU")
        
    async def _emergency_buffer_flush(self):
        """Emergency flush of event buffer to free memory"""
        batch = self.event_buffer.get_batch(max_size=50)
        if batch:
            logger.warning(f"Emergency flush: sending {len(batch)} events")
            # This would send the batch immediately
            
    async def _increase_compression(self):
        """Increase compression to save bandwidth"""
        # This would signal to use more aggressive compression
        logger.info("Increasing compression aggressiveness to save bandwidth")
        
    def process_telemetry_batch(self, events: List[Dict]) -> Tuple[bytes, Dict]:
        """Process a batch of telemetry events with optimization"""
        if not events:
            return b'', {}
            
        # Convert to JSON
        batch_data = {
            'batch_id': f"batch_{int(time.time())}",
            'timestamp': datetime.now().isoformat(),
            'event_count': len(events),
            'events': events
        }
        
        json_data = json.dumps(batch_data, separators=(',', ':')).encode('utf-8')
        
        # Apply compression
        compressed_data, algorithm, ratio = self.compression_engine.compress_data(json_data)
        
        # Update statistics
        self.performance_stats['bandwidth_saved_bytes'] += len(json_data) - len(compressed_data)
        
        processing_metadata = {
            'original_size': len(json_data),
            'compressed_size': len(compressed_data),
            'compression_algorithm': algorithm,
            'compression_ratio': ratio,
            'events_processed': len(events),
            'processing_timestamp': datetime.now().isoformat()
        }
        
        return compressed_data, processing_metadata
        
    def add_telemetry_event(self, event: Dict) -> bool:
        """Add telemetry event to buffer"""
        return self.event_buffer.add_event(event)
        
    def should_transmit_batch(self) -> bool:
        """Check if we should transmit a batch"""
        # Check buffer state
        if self.event_buffer.should_flush():
            return True
            
        # Check resource constraints
        metrics = self.resource_monitor.collect_metrics()
        
        # If resources are constrained, transmit to free up space
        if (metrics.memory_usage_mb > self.constraints.max_memory_mb * 0.8 or
            metrics.cpu_usage_percent > self.constraints.max_cpu_percent * 0.8):
            return True
            
        return False
        
    def get_transmission_batch(self) -> Tuple[bytes, Dict]:
        """Get optimized batch for transmission"""
        # Get events from buffer
        events = self.event_buffer.get_batch()
        
        if not events:
            return b'', {}
            
        # Process with optimization
        return self.process_telemetry_batch(events)
        
    def get_optimization_stats(self) -> Dict:
        """Get comprehensive optimization statistics"""
        compression_stats = self.compression_engine.get_compression_stats()
        buffer_stats = self.event_buffer.get_stats()
        resource_recommendations = self.resource_monitor.get_resource_recommendation()
        
        return {
            'edge_optimization': {
                'optimization_cycles': self.performance_stats['optimization_cycles'],
                'bandwidth_saved_bytes': self.performance_stats['bandwidth_saved_bytes'],
                'adaptive_mode': self.adaptive_mode,
                'constraints': asdict(self.constraints)
            },
            'compression': compression_stats,
            'buffer': buffer_stats,
            'resources': resource_recommendations,
            'alerts': self.resource_monitor.alerts[-10:]  # Last 10 alerts
        }
        
    def _log_performance_summary(self, metrics: EdgeMetrics):
        """Log performance summary"""
        stats = self.get_optimization_stats()
        
        logger.info(f"Edge Performance Summary:")
        logger.info(f"  CPU: {metrics.cpu_usage_percent:.1f}% | Memory: {metrics.memory_usage_mb:.1f}MB")
        logger.info(f"  Queue: {metrics.queue_depth} events | Compression: {stats['compression']['overall_compression_ratio']:.2f}")
        logger.info(f"  Bandwidth saved: {stats['edge_optimization']['bandwidth_saved_bytes']} bytes")
        logger.info(f"  Uptime: {metrics.uptime_seconds:.0f}s")

# Usage example and integration
class EdgeAgentController:
    """Main controller for edge agent deployment"""
    
    def __init__(self, config: Dict):
        # Parse configuration
        constraints_config = config.get('resource_constraints', {})
        self.constraints = ResourceConstraints(
            max_cpu_percent=constraints_config.get('max_cpu_percent', 50.0),
            max_memory_mb=constraints_config.get('max_memory_mb', 256),
            max_storage_mb=constraints_config.get('max_storage_mb', 1024),
            max_bandwidth_kbps=constraints_config.get('max_bandwidth_kbps', 100),
            max_concurrent_connections=constraints_config.get('max_concurrent_connections', 10),
            max_queue_size=constraints_config.get('max_queue_size', 1000),
            max_batch_age_seconds=constraints_config.get('max_batch_age_seconds', 30)
        )
        
        self.optimizer = EdgeOptimizer(self.constraints)
        self.is_running = False
        
    async def start(self):
        """Start the edge agent controller"""
        logger.info("Starting edge agent controller")
        self.is_running = True
        
        # Start optimization loop
        optimization_task = asyncio.create_task(
            self.optimizer.start_optimization_loop()
        )
        
        # Start transmission loop
        transmission_task = asyncio.create_task(
            self._transmission_loop()
        )
        
        # Wait for tasks
        await asyncio.gather(optimization_task, transmission_task)
        
    async def _transmission_loop(self):
        """Main transmission loop"""
        while self.is_running:
            try:
                if self.optimizer.should_transmit_batch():
                    compressed_data, metadata = self.optimizer.get_transmission_batch()
                    
                    if compressed_data:
                        logger.debug(f"Transmitting batch: {metadata}")
                        # This would send to the EventBus
                        await self._transmit_to_eventbus(compressed_data, metadata)
                
                await asyncio.sleep(1.0)  # Check every second
                
            except Exception as e:
                logger.error(f"Transmission loop error: {e}")
                await asyncio.sleep(5.0)
                
    async def _transmit_to_eventbus(self, data: bytes, metadata: Dict):
        """Transmit data to EventBus"""
        # This would integrate with the existing EventBus client
        # For now, just log the transmission
        logger.info(f"Transmitting {len(data)} bytes to EventBus (compressed from {metadata.get('original_size', 0)} bytes)")
        
    def add_telemetry(self, event: Dict):
        """Add telemetry event (called by protocol collectors)"""
        return self.optimizer.add_telemetry_event(event)
        
    def get_status(self) -> Dict:
        """Get edge agent status"""
        return {
            'is_running': self.is_running,
            'constraints': asdict(self.constraints),
            'optimization_stats': self.optimizer.get_optimization_stats()
        }

# Example configuration for different deployment scenarios
EDGE_CONFIGS = {
    'raspberry_pi': {
        'resource_constraints': {
            'max_cpu_percent': 60.0,
            'max_memory_mb': 200,
            'max_storage_mb': 500,
            'max_bandwidth_kbps': 50,
            'max_concurrent_connections': 5,
            'max_queue_size': 500,
            'max_batch_age_seconds': 60
        }
    },
    'industrial_gateway': {
        'resource_constraints': {
            'max_cpu_percent': 40.0,
            'max_memory_mb': 128,
            'max_storage_mb': 256,
            'max_bandwidth_kbps': 25,
            'max_concurrent_connections': 3,
            'max_queue_size': 200,
            'max_batch_age_seconds': 120
        }
    },
    'medical_device_hub': {
        'resource_constraints': {
            'max_cpu_percent': 30.0,
            'max_memory_mb': 64,
            'max_storage_mb': 128,
            'max_bandwidth_kbps': 10,
            'max_concurrent_connections': 2,
            'max_queue_size': 100,
            'max_batch_age_seconds': 300
        }
    }
}

if __name__ == "__main__":
    async def main():
        # Example: Deploy on Raspberry Pi
        config = EDGE_CONFIGS['raspberry_pi']
        controller = EdgeAgentController(config)
        
        # Simulate adding telemetry events
        for i in range(10):
            event = {
                'event_id': f'test_{i}',
                'device_id': 'edge_device_001',
                'timestamp': datetime.now().isoformat(),
                'event_type': 'METRIC',
                'data': {'temperature': 23.5 + i, 'humidity': 45.2}
            }
            controller.add_telemetry(event)
            
        # Start the controller
        await controller.start()
    
    asyncio.run(main())
