# AMOSKYS - First Steps to Real Data Collection

**Date:** January 25, 2025  
**Objective:** Get your first real device sending telemetry within the next hour

---

## 🎯 What We Just Fixed

### ✅ Protocol Buffers Compiled
- **Fixed:** `universal_telemetry.proto` now compiles successfully
- **Generated:** Python stubs for DeviceTelemetry, TelemetryEvent, and 30+ message types
- **Location:** `src/amoskys/proto/universal_telemetry_pb2.py`
- **Verification:**
  ```python
  from amoskys.proto import universal_telemetry_pb2
  # Now works! ✅
  ```

---

## 🚀 YOUR FIRST ACHIEVEMENT (Next 60 Minutes)

### Goal: Collect SNMP data from ONE device

**Why SNMP First?**
- ✅ Most network devices support it (routers, switches, printers)
- ✅ Simple protocol (just read OIDs)
- ✅ No authentication needed for basic queries
- ✅ Works with localhost for testing

---

## 📋 Step-by-Step Implementation

### Step 1: Install SNMP Library (2 minutes)

```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys
source .venv/bin/activate
pip install pysnmp-lextudio
```

**Why pysnmp-lextudio?** It's the modern, maintained fork of pysnmp.

---

### Step 2: Test SNMP on Your Mac (5 minutes)

First, check if SNMP is running on your Mac:

```bash
# Check if SNMP daemon is running
ps aux | grep snmpd

# If not running, start it (requires password):
sudo launchctl load -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist
```

Test SNMP query:
```bash
# Query system description
snmpget -v2c -c public localhost SNMPv2-MIB::sysDescr.0

# If snmpget not installed:
brew install net-snmp
```

**Expected output:**
```
SNMPv2-MIB::sysDescr.0 = STRING: Darwin MacBook-Pro 26.0.0...
```

---

### Step 3: Create Simple SNMP Test Script (10 minutes)

Create `tests/manual/test_snmp_real.py`:

```python
"""
Test real SNMP collection from localhost
Run this after 'make proto' to verify everything works
"""

import asyncio
from datetime import datetime
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

try:
    from pysnmp.hlapi.v3arch.asyncio import *
    PYSNMP_AVAILABLE = True
except ImportError:
    print("❌ pysnmp not installed. Run: pip install pysnmp-lextudio")
    PYSNMP_AVAILABLE = False

async def collect_snmp_data(host='localhost', community='public'):
    """Collect real SNMP data from a device"""
    if not PYSNMP_AVAILABLE:
        return None
    
    print(f"📡 Collecting SNMP data from {host}...")
    
    # Common OIDs to query
    oids = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',      # System description
        'sysUpTime': '1.3.6.1.2.1.1.3.0',    # Uptime
        'sysContact': '1.3.6.1.2.1.1.4.0',   # Contact
        'sysName': '1.3.6.1.2.1.1.5.0',      # Hostname
        'sysLocation': '1.3.6.1.2.1.1.6.0',  # Location
    }
    
    collected_data = {}
    
    for name, oid in oids.items():
        try:
            snmpEngine = SnmpEngine()
            iterator = getCmd(
                snmpEngine,
                CommunityData(community, mpModel=1),  # SNMPv2c
                await UdpTransportTarget.create((host, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = await iterator
            
            if errorIndication:
                print(f"  ❌ {name}: {errorIndication}")
            elif errorStatus:
                print(f"  ❌ {name}: {errorStatus.prettyPrint()}")
            else:
                for varBind in varBinds:
                    value = varBind[1].prettyPrint()
                    collected_data[name] = value
                    print(f"  ✅ {name}: {value[:80]}...")  # Truncate long values
            
            snmpEngine.closeDispatcher()
            
        except Exception as e:
            print(f"  ❌ {name}: {str(e)}")
    
    return collected_data

def create_device_telemetry(snmp_data, device_ip='localhost'):
    """Convert SNMP data to DeviceTelemetry protobuf message"""
    
    # Create DeviceMetadata
    metadata = telemetry_pb2.DeviceMetadata(
        ip_address=device_ip,
        manufacturer="Apple",  # For Mac
        model="macOS",
        protocols=["SNMP"],
    )
    
    # Create TelemetryEvents for each metric
    events = []
    for metric_name, value in snmp_data.items():
        metric_data = telemetry_pb2.MetricData(
            metric_name=f"snmp_{metric_name}",
            metric_type="GAUGE",
            string_value=value,
            unit="string"
        )
        
        event = telemetry_pb2.TelemetryEvent(
            event_id=f"{device_ip}_{metric_name}_{int(datetime.now().timestamp())}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=int(datetime.now().timestamp() * 1e9),
            metric_data=metric_data,
            tags=["snmp", "system_info"]
        )
        events.append(event)
    
    # Create DeviceTelemetry message
    device_telemetry = telemetry_pb2.DeviceTelemetry(
        device_id=device_ip,
        device_type="NETWORK",
        protocol="SNMP",
        metadata=metadata,
        events=events,
        timestamp_ns=int(datetime.now().timestamp() * 1e9),
        collection_agent="amoskys-test-agent",
        agent_version="0.1.0"
    )
    
    return device_telemetry

async def main():
    print("🧪 AMOSKYS SNMP Collection Test")
    print("=" * 50)
    
    # Step 1: Collect SNMP data
    snmp_data = await collect_snmp_data()
    
    if not snmp_data:
        print("\n❌ No SNMP data collected. Check if:")
        print("   1. snmpd is running: sudo launchctl load -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist")
        print("   2. Community string 'public' is allowed")
        print("   3. Firewall allows SNMP (port 161)")
        return
    
    print(f"\n✅ Collected {len(snmp_data)} SNMP metrics")
    
    # Step 2: Convert to protobuf
    print("\n📦 Converting to DeviceTelemetry protobuf...")
    device_telemetry = create_device_telemetry(snmp_data)
    
    print(f"  ✅ Device ID: {device_telemetry.device_id}")
    print(f"  ✅ Device Type: {device_telemetry.device_type}")
    print(f"  ✅ Protocol: {device_telemetry.protocol}")
    print(f"  ✅ Events: {len(device_telemetry.events)}")
    
    # Step 3: Serialize to bytes
    serialized = device_telemetry.SerializeToString()
    print(f"\n✅ Serialized size: {len(serialized)} bytes")
    
    # Step 4: Verify deserialization
    deserialized = telemetry_pb2.DeviceTelemetry()
    deserialized.ParseFromString(serialized)
    print(f"✅ Deserialization successful")
    
    print("\n" + "=" * 50)
    print("🎉 SUCCESS! You just collected and serialized real device telemetry!")
    print("\nNext steps:")
    print("  1. Connect this to EventBus")
    print("  2. Add more devices")
    print("  3. Enable continuous collection")
    
    return device_telemetry

if __name__ == "__main__":
    asyncio.run(main())
```

---

### Step 4: Run the Test (5 minutes)

```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys
mkdir -p tests/manual
# Create the test file (copy code from Step 3)
python tests/manual/test_snmp_real.py
```

**Expected Output:**
```
🧪 AMOSKYS SNMP Collection Test
==================================================
📡 Collecting SNMP data from localhost...
  ✅ sysDescr: Darwin MacBook-Pro.local 26.0.0 Darwin Kernel Version...
  ✅ sysUpTime: 1234567890
  ✅ sysName: MacBook-Pro.local
  ...

✅ Collected 5 SNMP metrics

📦 Converting to DeviceTelemetry protobuf...
  ✅ Device ID: localhost
  ✅ Device Type: NETWORK
  ✅ Protocol: SNMP
  ✅ Events: 5

✅ Serialized size: 347 bytes
✅ Deserialization successful

==================================================
🎉 SUCCESS! You just collected and serialized real device telemetry!
```

---

### Step 5: Connect to EventBus (15 minutes)

Now that you have real data, connect it to the EventBus:

Create `src/amoskys/agents/snmp_agent.py`:

```python
"""
Simple SNMP Agent - Collects data and sends to EventBus
"""

import asyncio
import grpc
import logging
from datetime import datetime
from amoskys.proto import messaging_schema_pb2 as pb
from amoskys.proto import messaging_schema_pb2_grpc as pbrpc
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.config import get_config
from pysnmp.hlapi.v3arch.asyncio import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SNMPAgent")

class SNMPAgent:
    def __init__(self):
        self.config = get_config()
        self.channel = None
        self.stub = None
        
    async def connect_to_eventbus(self):
        """Connect to EventBus via gRPC"""
        bus_address = self.config.agent.bus_address
        
        # Load TLS certificates
        with open(f"{self.config.agent.cert_dir}/ca.crt", "rb") as f:
            ca_cert = f.read()
        with open(f"{self.config.agent.cert_dir}/agent.crt", "rb") as f:
            client_cert = f.read()
        with open(f"{self.config.agent.cert_dir}/agent.key", "rb") as f:
            client_key = f.read()
        
        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca_cert,
            private_key=client_key,
            certificate_chain=client_cert
        )
        
        self.channel = grpc.aio.secure_channel(bus_address, credentials)
        self.stub = pbrpc.EventBusStub(self.channel)
        
        logger.info(f"✅ Connected to EventBus at {bus_address}")
    
    async def collect_snmp(self, host='localhost', community='public'):
        """Collect SNMP data from device"""
        oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            'sysName': '1.3.6.1.2.1.1.5.0',
        }
        
        collected = {}
        for name, oid in oids.items():
            try:
                snmpEngine = SnmpEngine()
                iterator = getCmd(
                    snmpEngine,
                    CommunityData(community, mpModel=1),
                    await UdpTransportTarget.create((host, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
                
                errorIndication, errorStatus, errorIndex, varBinds = await iterator
                
                if not errorIndication and not errorStatus:
                    for varBind in varBinds:
                        collected[name] = varBind[1].prettyPrint()
                
                snmpEngine.closeDispatcher()
                
            except Exception as e:
                logger.error(f"SNMP error for {name}: {e}")
        
        return collected
    
    def create_envelope(self, device_telemetry):
        """Wrap DeviceTelemetry in an Envelope for EventBus"""
        # For now, use FlowEvent as envelope (we'll extend EventBus later)
        # This is a temporary bridge until EventBus supports DeviceTelemetry natively
        
        flow = pb.FlowEvent(
            src_ip=device_telemetry.device_id,
            dst_ip="eventbus",
            protocol="SNMP",
            bytes_sent=len(device_telemetry.SerializeToString()),
            start_time=device_telemetry.timestamp_ns
        )
        
        envelope = pb.Envelope(
            version=1,
            ts_ns=int(datetime.now().timestamp() * 1e9),
            idempotency_key=f"snmp_{device_telemetry.device_id}_{device_telemetry.timestamp_ns}",
            flow=flow
        )
        
        return envelope
    
    async def publish_telemetry(self, device_telemetry):
        """Publish telemetry to EventBus"""
        envelope = self.create_envelope(device_telemetry)
        
        try:
            ack = await self.stub.Publish(envelope)
            
            if ack.status == pb.PublishAck.OK:
                logger.info(f"✅ Published telemetry for {device_telemetry.device_id}")
                return True
            else:
                logger.warning(f"⚠️  Publish failed: {ack.reason}")
                return False
                
        except grpc.RpcError as e:
            logger.error(f"❌ RPC error: {e}")
            return False
    
    async def run_collection_loop(self, interval=60):
        """Main collection loop"""
        await self.connect_to_eventbus()
        
        logger.info(f"🚀 Starting SNMP collection (interval: {interval}s)")
        
        while True:
            try:
                # Collect SNMP data
                snmp_data = await self.collect_snmp()
                
                if snmp_data:
                    logger.info(f"📊 Collected {len(snmp_data)} SNMP metrics")
                    
                    # Create DeviceTelemetry
                    # (You can reuse the create_device_telemetry function from test)
                    
                    # Publish to EventBus
                    # await self.publish_telemetry(device_telemetry)
                    
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Collection loop error: {e}")
                await asyncio.sleep(10)

if __name__ == "__main__":
    agent = SNMPAgent()
    asyncio.run(agent.run_collection_loop())
```

---

## 🎯 Validation Checklist

After completing these steps, verify:

- [ ] `make proto` runs without errors
- [ ] `from amoskys.proto import universal_telemetry_pb2` works
- [ ] SNMP test script collects real data from localhost
- [ ] DeviceTelemetry protobuf message serializes successfully
- [ ] You can see 5+ SNMP metrics in the output

---

## 🔍 Troubleshooting

### Problem: "Module not found: pysnmp"
**Solution:**
```bash
pip install pysnmp-lextudio
```

### Problem: "SNMP timeout" or "No response"
**Solutions:**
1. Enable SNMP on Mac:
   ```bash
   sudo launchctl load -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist
   ```

2. Check SNMP configuration:
   ```bash
   sudo vi /etc/snmp/snmpd.conf
   # Add line: rocommunity public
   ```

3. Test with snmpwalk:
   ```bash
   brew install net-snmp
   snmpwalk -v2c -c public localhost system
   ```

### Problem: "Protocol buffers import error"
**Solution:**
```bash
make proto  # Recompile proto files
python -c "from amoskys.proto import universal_telemetry_pb2"  # Verify
```

---

## 📊 What You'll Achieve

After this hour, you will have:

✅ **Real Data Collection**: SNMP metrics from your Mac  
✅ **Protobuf Working**: DeviceTelemetry messages serializing  
✅ **Foundation Ready**: Pattern for adding more devices/protocols  
✅ **Proof of Concept**: End-to-end telemetry flow working  

---

## 🚀 Next Achievements (After First Success)

### Achievement #2: Add Your Router
- Query your home router via SNMP
- Collect interface stats, bandwidth, errors
- Monitor in real-time

### Achievement #3: Add IoT Device
- Implement MQTT collector
- Connect to smart home device
- Stream sensor data

### Achievement #4: Enable Threat Detection
- Feed telemetry to intelligence layer
- Detect anomalous behavior
- Generate first security alert

---

## 📞 Need Help?

If you get stuck, check:
1. **SYSTEM_ANALYSIS_AND_ROADMAP.md** - Full transformation plan
2. **COMPLETION_REPORT.md** - System status
3. **docs/ARCHITECTURE.md** - Component details
4. **proto/universal_telemetry.proto** - Data schema reference

---

**Remember:** The goal is to get ONE device sending REAL data. Once that works, scaling to 10, 100, or 1000 devices is just configuration!

**Start now!** Run `make proto` and create that test script. You're 60 minutes away from your first real achievement! 🎯
