"""
AMOSKYS Enhanced SNMP Metrics Collector
Config-driven SNMP agent with support for tables, profiles, and thresholds
"""

import yaml
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger("SNMPMetricsCollector")


@dataclass
class MetricDefinition:
    """Definition of a single SNMP metric"""

    name: str
    oid: str
    type: str  # string, counter, gauge
    description: str
    severity: str
    unit: Optional[str] = None
    is_table: bool = False
    vendor_specific: Optional[str] = None
    thresholds: Optional[Dict[str, float]] = None


@dataclass
class MetricCategory:
    """Category of related metrics"""

    name: str
    enabled: bool
    description: str
    metrics: List[MetricDefinition]


class SNMPMetricsConfig:
    """Configuration manager for SNMP metrics"""

    def __init__(self, config_path: str):
        """Load configuration from YAML file

        Args:
            config_path: Path to snmp_metrics_config.yaml
        """
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.categories: Dict[str, MetricCategory] = {}
        self._parse_config()

    def _parse_config(self):
        """Parse configuration into structured objects"""
        metrics_config = self.config.get("metrics", {})

        for category_name, category_data in metrics_config.items():
            metrics = []

            for oid_def in category_data.get("oids", []):
                metric = MetricDefinition(
                    name=oid_def["name"],
                    oid=oid_def["oid"],
                    type=oid_def.get("type", "string"),
                    description=oid_def["description"],
                    severity=oid_def.get("severity", "INFO"),
                    unit=oid_def.get("unit"),
                    is_table=oid_def.get("is_table", False),
                    vendor_specific=oid_def.get("vendor_specific"),
                    thresholds=oid_def.get("thresholds"),
                )
                metrics.append(metric)

            category = MetricCategory(
                name=category_name,
                enabled=category_data.get("enabled", False),
                description=category_data.get("description", ""),
                metrics=metrics,
            )

            self.categories[category_name] = category

    def get_enabled_metrics(self) -> List[MetricDefinition]:
        """Get all metrics from enabled categories

        Returns:
            List of metric definitions to collect
        """
        enabled_metrics = []

        for category in self.categories.values():
            if category.enabled:
                enabled_metrics.extend(category.metrics)

        return enabled_metrics

    def apply_profile(self, profile_name: str):
        """Apply a predefined profile

        Args:
            profile_name: Name of profile from config (minimal, standard, full, etc.)
        """
        profiles = self.config.get("profiles", {})

        if profile_name not in profiles:
            raise ValueError(f"Profile '{profile_name}' not found")

        profile = profiles[profile_name]
        enabled_categories = profile.get("enabled_categories", [])

        # Disable all categories first
        for category in self.categories.values():
            category.enabled = False

        # Enable specified categories
        for category_name in enabled_categories:
            if category_name in self.categories:
                self.categories[category_name].enabled = True

        logger.info(f"Applied profile '{profile_name}': {profile['description']}")
        logger.info(f"Enabled categories: {', '.join(enabled_categories)}")

    def enable_category(self, category_name: str):
        """Enable a specific category

        Args:
            category_name: Name of category to enable
        """
        if category_name in self.categories:
            self.categories[category_name].enabled = True
            logger.info(f"Enabled category: {category_name}")
        else:
            logger.warning(f"Category not found: {category_name}")

    def disable_category(self, category_name: str):
        """Disable a specific category

        Args:
            category_name: Name of category to disable
        """
        if category_name in self.categories:
            self.categories[category_name].enabled = False
            logger.info(f"Disabled category: {category_name}")

    def get_metric_count(self) -> Tuple[int, int]:
        """Get count of enabled vs total metrics

        Returns:
            Tuple of (enabled_count, total_count)
        """
        total = sum(len(cat.metrics) for cat in self.categories.values())
        enabled = sum(
            len(cat.metrics) for cat in self.categories.values() if cat.enabled
        )

        return enabled, total

    def list_categories(self) -> Dict[str, bool]:
        """List all categories and their enabled status

        Returns:
            Dictionary of category_name: enabled status
        """
        return {name: cat.enabled for name, cat in self.categories.items()}

    def check_threshold(self, metric_name: str, value: float) -> Optional[str]:
        """Check if a metric value exceeds thresholds

        Args:
            metric_name: Name of the metric
            value: Current value

        Returns:
            'warning', 'critical', or None
        """
        for category in self.categories.values():
            for metric in category.metrics:
                if metric.name == metric_name and metric.thresholds:
                    if value >= metric.thresholds.get("critical", float("inf")):
                        return "critical"
                    elif value >= metric.thresholds.get("warning", float("inf")):
                        return "warning"

        return None


class EnhancedSNMPCollector:
    """Enhanced SNMP collector with config-driven metrics"""

    def __init__(self, metrics_config: SNMPMetricsConfig):
        """Initialize collector with metrics configuration

        Args:
            metrics_config: Loaded SNMPMetricsConfig instance
        """
        self.metrics_config = metrics_config
        self.advanced_settings = metrics_config.config.get("advanced", {})

    async def collect_metric(
        self, host: str, community: str, metric: MetricDefinition
    ) -> Dict[str, Any]:
        """Collect a single metric or table

        Args:
            host: Target device
            community: SNMP community string
            metric: Metric definition

        Returns:
            Dictionary with metric data
        """
        # Import here to avoid circular dependency
        from pysnmp.hlapi.v1arch.asyncio import (
            get_cmd,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
        )

        results = {}

        if metric.is_table:
            # Table walk - collect multiple instances
            results[metric.name] = await self._collect_table(host, community, metric)
        else:
            # Single OID collection
            try:
                error_indication, error_status, error_index, var_binds = await get_cmd(
                    CommunityData(community),
                    await UdpTransportTarget.create((host, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity(metric.oid)),
                )

                if error_indication:
                    logger.warning(f"SNMP error for {metric.name}: {error_indication}")
                    return {}

                if error_status:
                    logger.warning(f"SNMP error for {metric.name}: {error_status}")
                    return {}

                for var_bind in var_binds:
                    value = str(var_bind[1])
                    results[metric.name] = {
                        "value": value,
                        "oid": metric.oid,
                        "type": metric.type,
                        "unit": metric.unit,
                        "severity": metric.severity,
                        "description": metric.description,
                    }

                    # Check thresholds if numeric
                    if metric.type in ["gauge", "counter"] and metric.thresholds:
                        try:
                            numeric_value = float(value)
                            threshold_status = self.metrics_config.check_threshold(
                                metric.name, numeric_value
                            )
                            if threshold_status:
                                results[metric.name][
                                    "threshold_status"
                                ] = threshold_status
                        except ValueError:
                            pass

            except Exception as e:
                logger.error(f"Error collecting {metric.name}: {e}")

        return results

    async def _collect_table(
        self, host: str, community: str, metric: MetricDefinition
    ) -> List[Dict[str, Any]]:
        """Collect SNMP table data

        Args:
            host: Target device
            community: SNMP community string
            metric: Table metric definition

        Returns:
            List of table rows
        """
        # Import here
        from pysnmp.hlapi.v1arch.asyncio import (
            next_cmd,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
        )

        table_data = []
        max_rows = self.advanced_settings.get("table_walk", {}).get("max_rows", 100)

        try:
            # Start table walk
            last_oid = ObjectIdentity(metric.oid)

            for row_idx in range(max_rows):
                error_indication, error_status, error_index, var_binds = await next_cmd(
                    CommunityData(community),
                    await UdpTransportTarget.create((host, 161)),
                    ContextData(),
                    ObjectType(last_oid),
                )

                if error_indication or error_status:
                    break

                for var_bind in var_binds:
                    oid = str(var_bind[0])
                    value = str(var_bind[1])

                    # Check if still in table
                    if not oid.startswith(metric.oid):
                        return table_data

                    # Extract index from OID
                    index = oid[len(metric.oid) :].lstrip(".")

                    table_data.append({"index": index, "value": value, "oid": oid})

                    last_oid = ObjectIdentity(oid)

        except Exception as e:
            logger.error(f"Error walking table {metric.name}: {e}")

        return table_data

    async def collect_all(self, host: str, community: str) -> Dict[str, Any]:
        """Collect all enabled metrics from a device

        Args:
            host: Target device
            community: SNMP community string

        Returns:
            Dictionary of all collected metrics
        """
        all_results = {}
        enabled_metrics = self.metrics_config.get_enabled_metrics()

        logger.info(f"Collecting {len(enabled_metrics)} metrics from {host}")

        # Parallel collection if enabled
        if self.advanced_settings.get("parallel_collection", True):
            max_concurrent = self.advanced_settings.get("max_concurrent_requests", 10)

            # Collect in batches
            for i in range(0, len(enabled_metrics), max_concurrent):
                batch = enabled_metrics[i : i + max_concurrent]
                tasks = [
                    self.collect_metric(host, community, metric) for metric in batch
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, dict):
                        all_results.update(result)
        else:
            # Sequential collection
            for metric in enabled_metrics:
                result = await self.collect_metric(host, community, metric)
                all_results.update(result)

        return all_results


# Example usage
async def main():
    """Example of using the enhanced SNMP collector"""

    # Load configuration
    config = SNMPMetricsConfig("config/snmp_metrics_config.yaml")

    # Apply a profile
    config.apply_profile("standard")  # or 'minimal', 'full', etc.

    # Or manually enable categories
    # config.enable_category('cpu')
    # config.enable_category('network_interfaces')

    # Show what will be collected
    enabled, total = config.get_metric_count()
    print(f"Enabled {enabled} out of {total} metrics")
    print(f"Categories: {config.list_categories()}")

    # Create collector
    collector = EnhancedSNMPCollector(config)

    # Collect from device
    results = await collector.collect_all("localhost", "public")

    print(f"\nCollected {len(results)} metrics:")
    for name, data in results.items():
        if isinstance(data, dict) and "value" in data:
            print(f"  {name}: {data['value']} {data.get('unit', '')}")
        else:
            print(f"  {name}: [table with {len(data)} rows]")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())


# Export public API
__all__ = [
    "SNMPMetricsConfig",
    "EnhancedSNMPCollector",
    "MetricDefinition",
    "MetricCategory",
]
