# ==============================================================================
# Product:       lh-api-auditor (lh-api)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures for lh-api-auditor."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_clean_openapi() -> str:
    """Return a hardened, compliant OpenAPI 3.0 YAML specification."""
    return """
    openapi: 3.0.3
    info:
      title: Secure API Service
      version: 1.0.0
    servers:
      - url: https://api.example.com/v1
    security:
      - OAuth2Security:
          - read:users
          - write:users
    paths:
      /users/{userId}:
        get:
          summary: Retrieve a user profile
          operationId: getUser
          parameters:
            - name: userId
              in: path
              required: true
              schema:
                type: string
                format: uuid
          responses:
            '200':
              description: User profile found
              headers:
                X-RateLimit-Limit:
                  schema:
                    type: integer
                X-RateLimit-Remaining:
                  schema:
                    type: integer
            '429':
              description: Rate limit exceeded
        post:
          summary: Update user profile
          operationId: updateUser
          parameters:
            - name: userId
              in: path
              required: true
              schema:
                type: string
                format: uuid
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  additionalProperties: false
                  properties:
                    fullName:
                      type: string
                      maxLength: 100
          responses:
            '200':
              description: Profile updated
            '429':
              description: Rate limit exceeded
    components:
      securitySchemes:
        OAuth2Security:
          type: oauth2
          flows:
            authorizationCode:
              authorizationUrl: https://auth.example.com/oauth/authorize
              tokenUrl: https://auth.example.com/oauth/token
              scopes:
                read:users: Read user profile
                write:users: Modify user profile
    """


@pytest.fixture
def sample_clean_graphql() -> str:
    """Return a secure, compliant GraphQL schema."""
    return """
    directive @auth(role: String) on FIELD_DEFINITION
    directive @limit(max: Int) on ARGUMENT_DEFINITION

    type User {
      id: ID!
      username: String!
      email: String!
    }

    type Query {
      getUser(id: ID!): User
    }

    type Mutation {
      updateUser(id: ID!, email: String!): User @auth(role: "USER")
      deleteUser(id: ID!): Boolean @auth(role: "ADMIN")
    }
    """
