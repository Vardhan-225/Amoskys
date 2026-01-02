"""
AMOSKYS API Documentation Generator
Generates OpenAPI/Swagger documentation for the API Gateway
"""

# Constants
APPLICATION_JSON = "application/json"


def generate_openapi_spec():
    """Generate OpenAPI 3.0 specification for AMOSKYS API"""
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "AMOSKYS Neural Security Command Platform API",
            "description": "RESTful API for the AMOSKYS Neural Security Command Platform - Agent management, event ingestion, and system monitoring",
            "version": "2.3.0",
            "contact": {"name": "AMOSKYS Security Team", "url": "https://amoskys.com"},
            "license": {"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
        },
        "servers": [
            {"url": "https://amoskys.com/api", "description": "Production server"},
            {"url": "http://localhost:8000/api", "description": "Development server"},
        ],
        "paths": {
            "/auth/login": {
                "post": {
                    "summary": "Agent Authentication",
                    "description": "Authenticate an agent and receive a JWT token",
                    "tags": ["Authentication"],
                    "requestBody": {
                        "required": True,
                        "content": {
                            APPLICATION_JSON: {
                                "schema": {
                                    "type": "object",
                                    "required": ["agent_id", "secret"],
                                    "properties": {
                                        "agent_id": {
                                            "type": "string",
                                            "example": "flowagent-001",
                                        },
                                        "secret": {
                                            "type": "string",
                                            "example": "secure-key",
                                        },
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Authentication successful",
                            "content": {
                                APPLICATION_JSON: {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {
                                                "type": "string",
                                                "example": "success",
                                            },
                                            "token": {"type": "string"},
                                            "agent_id": {"type": "string"},
                                            "role": {"type": "string"},
                                            "expires_in": {"type": "integer"},
                                        },
                                    }
                                }
                            },
                        },
                        "401": {"description": "Invalid credentials"},
                    },
                }
            },
            "/agents/ping": {
                "post": {
                    "summary": "Agent Heartbeat",
                    "description": "Send agent heartbeat and receive server instructions",
                    "tags": ["Agents"],
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Heartbeat acknowledged",
                            "content": {
                                APPLICATION_JSON: {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {
                                                "type": "string",
                                                "example": "pong",
                                            },
                                            "timestamp": {
                                                "type": "string",
                                                "format": "date-time",
                                            },
                                            "agent_id": {"type": "string"},
                                            "system_metrics": {"type": "object"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/events/submit": {
                "post": {
                    "summary": "Submit Security Event",
                    "description": "Submit a security event for processing",
                    "tags": ["Events"],
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            APPLICATION_JSON: {
                                "schema": {
                                    "type": "object",
                                    "required": [
                                        "event_type",
                                        "severity",
                                        "source_ip",
                                        "description",
                                    ],
                                    "properties": {
                                        "event_type": {
                                            "type": "string",
                                            "example": "network_anomaly",
                                        },
                                        "severity": {
                                            "type": "string",
                                            "enum": [
                                                "low",
                                                "medium",
                                                "high",
                                                "critical",
                                            ],
                                        },
                                        "source_ip": {
                                            "type": "string",
                                            "example": "192.168.1.100",
                                        },
                                        "destination_ip": {
                                            "type": "string",
                                            "example": "10.0.0.1",
                                        },
                                        "description": {
                                            "type": "string",
                                            "example": "Unusual network activity detected",
                                        },
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Event submitted successfully",
                            "content": {
                                APPLICATION_JSON: {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {
                                                "type": "string",
                                                "example": "success",
                                            },
                                            "event_id": {"type": "string"},
                                            "timestamp": {
                                                "type": "string",
                                                "format": "date-time",
                                            },
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/system/health": {
                "get": {
                    "summary": "System Health Check",
                    "description": "Get system health status (no authentication required)",
                    "tags": ["System"],
                    "responses": {
                        "200": {
                            "description": "System health information",
                            "content": {
                                APPLICATION_JSON: {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {
                                                "type": "string",
                                                "enum": [
                                                    "healthy",
                                                    "degraded",
                                                    "error",
                                                ],
                                            },
                                            "timestamp": {
                                                "type": "string",
                                                "format": "date-time",
                                            },
                                            "metrics": {"type": "object"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
        "tags": [
            {
                "name": "Authentication",
                "description": "Agent authentication and token management",
            },
            {"name": "Agents", "description": "Agent registration and management"},
            {
                "name": "Events",
                "description": "Security event ingestion and management",
            },
            {"name": "System", "description": "System health and monitoring"},
        ],
    }
    return spec
