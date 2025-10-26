#!/usr/bin/env python3
"""
AMOSKYS SNMP Metrics Configuration Manager

Quick configuration tool for enabling/disabling SNMP metric categories

Usage:
    python scripts/configure_metrics.py --profile full
    python scripts/configure_metrics.py --enable cpu memory network
    python scripts/configure_metrics.py --disable processes
    python scripts/configure_metrics.py --show
"""

import yaml
import argparse
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config" / "snmp_metrics_config.yaml"


def load_config():
    """Load SNMP metrics configuration"""
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)


def save_config(config):
    """Save SNMP metrics configuration"""
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, indent=2)
    print(f"✓ Configuration saved to {CONFIG_PATH}")


def apply_profile(profile_name):
    """Apply a predefined profile"""
    config = load_config()
    
    if 'profiles' not in config or profile_name not in config['profiles']:
        print(f"✗ Profile '{profile_name}' not found")
        print(f"Available profiles: {list(config.get('profiles', {}).keys())}")
        return
        
    profile = config['profiles'][profile_name]
    enabled_categories = profile.get('enabled_categories', [])
    
    print(f"\nApplying profile: {profile_name}")
    print(f"Description: {profile.get('description', 'N/A')}")
    print(f"\nEnabled categories: {enabled_categories}")
    
    # Update config
    for category in config['metrics']:
        if category in enabled_categories:
            config['metrics'][category]['enabled'] = True
            print(f"  ✓ Enabled: {category}")
        else:
            config['metrics'][category]['enabled'] = False
            print(f"  ✗ Disabled: {category}")
            
    save_config(config)
    show_status(config)


def enable_categories(categories):
    """Enable specific categories"""
    config = load_config()
    
    print(f"\nEnabling categories: {categories}")
    
    for category in categories:
        if category in config['metrics']:
            config['metrics'][category]['enabled'] = True
            print(f"  ✓ Enabled: {category}")
        else:
            print(f"  ✗ Category not found: {category}")
            
    save_config(config)
    show_status(config)


def disable_categories(categories):
    """Disable specific categories"""
    config = load_config()
    
    print(f"\nDisabling categories: {categories}")
    
    for category in categories:
        if category in config['metrics']:
            config['metrics'][category]['enabled'] = False
            print(f"  ✗ Disabled: {category}")
        else:
            print(f"  ✗ Category not found: {category}")
            
    save_config(config)
    show_status(config)


def show_status(config=None):
    """Show current configuration status"""
    if config is None:
        config = load_config()
        
    print("\n" + "="*60)
    print("CURRENT CONFIGURATION STATUS")
    print("="*60)
    
    total_metrics = 0
    enabled_metrics = 0
    
    for category, settings in config['metrics'].items():
        is_enabled = settings.get('enabled', False)
        oids = settings.get('oids', [])
        metric_count = len(oids)
        
        total_metrics += metric_count
        if is_enabled:
            enabled_metrics += metric_count
            
        status = "✓ ENABLED " if is_enabled else "✗ DISABLED"
        print(f"\n{status} - {category}")
        print(f"  Description: {settings.get('description', 'N/A')}")
        print(f"  Metrics: {metric_count}")
        
        if is_enabled and metric_count <= 5:
            # Show metric names for enabled categories with few metrics
            for oid in oids:
                print(f"    - {oid.get('name', 'N/A')}")
                
    print(f"\n{'='*60}")
    print(f"TOTAL: {enabled_metrics}/{total_metrics} metrics enabled")
    print(f"{'='*60}\n")


def list_profiles():
    """List available profiles"""
    config = load_config()
    
    print("\n" + "="*60)
    print("AVAILABLE PROFILES")
    print("="*60)
    
    if 'profiles' not in config:
        print("No profiles found")
        return
        
    for name, profile in config['profiles'].items():
        print(f"\n{name}:")
        print(f"  Description: {profile.get('description', 'N/A')}")
        print(f"  Categories: {', '.join(profile.get('enabled_categories', []))}")
        
    print("")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Configure AMOSKYS SNMP metrics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show current status
  %(prog)s --show
  
  # Apply a profile
  %(prog)s --profile full
  
  # Enable specific categories
  %(prog)s --enable cpu memory network
  
  # Disable specific categories
  %(prog)s --disable processes disk
  
  # List available profiles
  %(prog)s --list-profiles
        """
    )
    
    parser.add_argument('--show', action='store_true',
                       help='Show current configuration status')
    parser.add_argument('--profile', type=str,
                       help='Apply a predefined profile (minimal, standard, full, etc.)')
    parser.add_argument('--enable', nargs='+', metavar='CATEGORY',
                       help='Enable specific categories')
    parser.add_argument('--disable', nargs='+', metavar='CATEGORY',
                       help='Disable specific categories')
    parser.add_argument('--list-profiles', action='store_true',
                       help='List available profiles')
    
    args = parser.parse_args()
    
    if args.list_profiles:
        list_profiles()
    elif args.profile:
        apply_profile(args.profile)
    elif args.enable:
        enable_categories(args.enable)
    elif args.disable:
        disable_categories(args.disable)
    elif args.show:
        show_status()
    else:
        parser.print_help()
        print("\nCurrent status:")
        show_status()


if __name__ == '__main__':
    main()
