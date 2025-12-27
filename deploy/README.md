# AMOSKYS Deployment Configurations

Deployment configurations for various environments and platforms.

## Directory Structure

### [`nginx/`](nginx/)
NGINX reverse proxy configuration for production deployments.

- `amoskys.conf` - NGINX server configuration

## Deployment Methods

### Local Development
```bash
./start_amoskys.sh
```

### Production
See [deployment documentation](../docs/operations/deployment.md) for production deployment guides.

## Configuration

Production configurations should be customized for your environment. Never commit:
- Private keys or certificates
- Production passwords or tokens
- Environment-specific IP addresses

Use environment variables or config templates instead.
