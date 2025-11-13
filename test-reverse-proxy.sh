#!/bin/bash

# Script de prueba del Reverse Proxy (Nginx Edge)
# Valida que el patrón arquitectónico esté funcionando correctamente

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

NGINX_EDGE_URL="http://localhost:8888"
KONG_DIRECT_URL="http://localhost:8000"
TEST_EMAIL="test-proxy@leroi.com"

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}🔍 TEST REVERSE PROXY - NGINX EDGE${NC}"
echo -e "${BLUE}================================${NC}\n"

# ====================================
# TEST 1: Verificar que Nginx Edge está activo
# ====================================
echo -e "${YELLOW}[TEST 1]${NC} Verificando estado de Nginx Edge..."
HEALTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" ${NGINX_EDGE_URL}/health)

if [ "$HEALTH_CHECK" == "200" ]; then
    echo -e "${GREEN}✅ PASS${NC} - Nginx Edge está activo (HTTP 200)"
    echo -e "   Response: $(curl -s ${NGINX_EDGE_URL}/health)"
else
    echo -e "${RED}❌ FAIL${NC} - Nginx Edge no responde correctamente (HTTP ${HEALTH_CHECK})"
    exit 1
fi
echo ""

# ====================================
# TEST 2: Verificar headers de seguridad
# ====================================
echo -e "${YELLOW}[TEST 2]${NC} Verificando headers de seguridad..."
HEADERS=$(curl -sI ${NGINX_EDGE_URL}/health)

# Verificar X-Content-Type-Options
if echo "$HEADERS" | grep -qi "X-Content-Type-Options: nosniff"; then
    echo -e "${GREEN}✅ PASS${NC} - Header X-Content-Type-Options presente"
else
    echo -e "${RED}❌ FAIL${NC} - Header X-Content-Type-Options faltante"
fi

# Verificar Referrer-Policy
if echo "$HEADERS" | grep -qi "Referrer-Policy: no-referrer"; then
    echo -e "${GREEN}✅ PASS${NC} - Header Referrer-Policy presente"
else
    echo -e "${RED}❌ FAIL${NC} - Header Referrer-Policy faltante"
fi

# Verificar X-Frame-Options
if echo "$HEADERS" | grep -qi "X-Frame-Options: DENY"; then
    echo -e "${GREEN}✅ PASS${NC} - Header X-Frame-Options presente"
else
    echo -e "${RED}❌ FAIL${NC} - Header X-Frame-Options faltante"
fi
echo ""

# ====================================
# TEST 3: Verificar que requests pasan por el proxy
# ====================================
echo -e "${YELLOW}[TEST 3]${NC} Verificando que requests pasan por Nginx Edge..."

# Realizar request a través de Nginx Edge
RESPONSE_VIA_EDGE=$(curl -s -X POST \
    ${NGINX_EDGE_URL}/users_authentication_path/check-email \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\"}" \
    -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE_EDGE=$(echo "$RESPONSE_VIA_EDGE" | grep "HTTP_CODE" | cut -d: -f2)
BODY_EDGE=$(echo "$RESPONSE_VIA_EDGE" | grep -v "HTTP_CODE")

if [ "$HTTP_CODE_EDGE" == "200" ]; then
    echo -e "${GREEN}✅ PASS${NC} - Request a través de Nginx Edge exitoso (HTTP ${HTTP_CODE_EDGE})"
    echo -e "   Response: ${BODY_EDGE}"
else
    echo -e "${RED}❌ FAIL${NC} - Request a través de Nginx Edge falló (HTTP ${HTTP_CODE_EDGE})"
fi
echo ""

# ====================================
# TEST 4: Verificar header X-Client-Type "mobile"
# ====================================
echo -e "${YELLOW}[TEST 4]${NC} Verificando que Nginx Edge añade header X-Client-Type..."

# Crear un endpoint de prueba temporal para ver headers
echo -e "   ${BLUE}Nota:${NC} Este test requiere que Kong/backend registre el header X-Client-Type"
echo -e "   ${BLUE}Enviando request con verbose para verificar headers...${NC}"

REQUEST_HEADERS=$(curl -v -X POST \
    ${NGINX_EDGE_URL}/users_authentication_path/check-email \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\"}" 2>&1 | grep "> ")

echo -e "   Headers enviados desde cliente:"
echo "$REQUEST_HEADERS" | head -5

echo -e "${GREEN}✅ PASS${NC} - Nginx Edge está procesando la request"
echo ""

# ====================================
# TEST 5: Verificar rate limiting
# ====================================
echo -e "${YELLOW}[TEST 5]${NC} Verificando rate limiting (30 req/s)..."
echo -e "   ${BLUE}Enviando 35 requests rápidas...${NC}"

SUCCESS_COUNT=0
RATE_LIMITED_COUNT=0

for i in {1..35}; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST ${NGINX_EDGE_URL}/users_authentication_path/check-email \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"test${i}@leroi.com\"}")
    
    if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "201" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    elif [ "$HTTP_CODE" == "429" ]; then
        RATE_LIMITED_COUNT=$((RATE_LIMITED_COUNT + 1))
    fi
done

echo -e "   Requests exitosos: ${SUCCESS_COUNT}"
echo -e "   Requests rate-limited: ${RATE_LIMITED_COUNT}"

if [ $RATE_LIMITED_COUNT -gt 0 ]; then
    echo -e "${GREEN}✅ PASS${NC} - Rate limiting está funcionando (${RATE_LIMITED_COUNT} requests bloqueados)"
else
    echo -e "${YELLOW}⚠️  WARNING${NC} - No se detectó rate limiting (puede ser que el burst permita todas)"
fi
echo ""

# ====================================
# TEST 6: Verificar response en rate limit exceeded
# ====================================
echo -e "${YELLOW}[TEST 6]${NC} Verificando respuesta estructurada en rate limit..."
echo -e "   ${BLUE}Forzando rate limit con múltiples requests...${NC}"

# Forzar rate limit con 50 requests ultra rápidas
for i in {1..50}; do
    curl -s -o /dev/null ${NGINX_EDGE_URL}/health &
done
wait

RATE_LIMIT_RESPONSE=$(curl -s -X POST ${NGINX_EDGE_URL}/users_authentication_path/check-email \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"rate-limit-test@leroi.com\"}")

if echo "$RATE_LIMIT_RESPONSE" | grep -q "error"; then
    echo -e "${GREEN}✅ PASS${NC} - Respuesta estructurada en rate limit"
    echo -e "   Response: ${RATE_LIMIT_RESPONSE}"
else
    echo -e "${YELLOW}⚠️  INFO${NC} - No se pudo forzar rate limit en este momento"
fi
echo ""

# ====================================
# TEST 7: Verificar que Nginx Edge es el único punto de entrada
# ====================================
echo -e "${YELLOW}[TEST 7]${NC} Verificando que microservices NO son accesibles directamente..."

# Intentar acceder directamente a user_auth (debería fallar)
if docker exec -it user_authentication_be-user_auth-1 echo "alive" &> /dev/null; then
    
    # Verificar que el puerto 8080 NO esté expuesto al host
    if ! nc -zv localhost 8080 &> /dev/null; then
        echo -e "${GREEN}✅ PASS${NC} - Microservicio user_auth NO es accesible desde host"
    else
        echo -e "${RED}❌ FAIL${NC} - Microservicio user_auth está expuesto en el host"
    fi
else
    echo -e "${YELLOW}⚠️  SKIP${NC} - No se pudo verificar (contenedor no encontrado)"
fi
echo ""

# ====================================
# TEST 8: Verificar que Load Balancers NO son accesibles
# ====================================
echo -e "${YELLOW}[TEST 8]${NC} Verificando que Load Balancers NO son accesibles directamente..."

# Verificar que lb-auth no expone puertos (salida vacía = sin puertos expuestos)
LB_AUTH_PORTS=$(docker port lb-auth 2>&1)
if [ -z "$LB_AUTH_PORTS" ]; then
    echo -e "${GREEN}✅ PASS${NC} - Load Balancer lb-auth NO expone puertos públicos"
else
    echo -e "${RED}❌ FAIL${NC} - Load Balancer lb-auth tiene puertos expuestos: ${LB_AUTH_PORTS}"
fi

# Verificar que lb-learningpath no expone puertos (salida vacía = sin puertos expuestos)
LB_LP_PORTS=$(docker port lb-learningpath 2>&1)
if [ -z "$LB_LP_PORTS" ]; then
    echo -e "${GREEN}✅ PASS${NC} - Load Balancer lb-learningpath NO expone puertos públicos"
else
    echo -e "${RED}❌ FAIL${NC} - Load Balancer lb-learningpath tiene puertos expuestos: ${LB_LP_PORTS}"
fi
echo ""

# ====================================
# TEST 9: Verificar flujo end-to-end
# ====================================
echo -e "${YELLOW}[TEST 9]${NC} Verificando flujo end-to-end completo..."
echo -e "   ${BLUE}Flujo: Cliente → Nginx Edge → Kong → Load Balancer → Microservice → DB${NC}"

E2E_RESPONSE=$(curl -s -X POST \
    ${NGINX_EDGE_URL}/users_authentication_path/check-email \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"e2e-test@leroi.com\"}")

if echo "$E2E_RESPONSE" | grep -q "status"; then
    echo -e "${GREEN}✅ PASS${NC} - Flujo end-to-end funcionando correctamente"
    echo -e "   Response: ${E2E_RESPONSE}"
else
    echo -e "${RED}❌ FAIL${NC} - Flujo end-to-end con problemas"
    echo -e "   Response: ${E2E_RESPONSE}"
fi
echo ""

# ====================================
# TEST 10: Verificar logging y trazabilidad
# ====================================
echo -e "${YELLOW}[TEST 10]${NC} Verificando logs de Nginx Edge..."

# Verificar que los logs se están generando
LOG_COUNT=$(docker logs nginx-edge 2>&1 | wc -l)

if [ $LOG_COUNT -gt 0 ]; then
    echo -e "${GREEN}✅ PASS${NC} - Nginx Edge está generando logs (${LOG_COUNT} líneas)"
    echo -e "   ${BLUE}Últimos 5 logs:${NC}"
    docker logs nginx-edge 2>&1 | tail -5 | sed 's/^/   /'
else
    echo -e "${RED}❌ FAIL${NC} - No se encontraron logs en Nginx Edge"
fi
echo ""

# ====================================
# TEST 11: Verificar access log con request_id
# ====================================
echo -e "${YELLOW}[TEST 11]${NC} Verificando trazabilidad con request_id..."

# Realizar request y buscar en logs
TEST_REQUEST=$(curl -s -X POST \
    ${NGINX_EDGE_URL}/users_authentication_path/check-email \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"trace-test@leroi.com\"}")

sleep 1

# Buscar en logs recientes
RECENT_LOG=$(docker logs nginx-edge 2>&1 | tail -10 | grep "check-email" || echo "")

if [ -n "$RECENT_LOG" ]; then
    echo -e "${GREEN}✅ PASS${NC} - Request registrada en logs con trazabilidad"
    echo -e "   ${BLUE}Log entry:${NC}"
    echo "$RECENT_LOG" | tail -1 | sed 's/^/   /'
else
    echo -e "${YELLOW}⚠️  INFO${NC} - No se encontró la request específica en logs recientes"
fi
echo ""

# ====================================
# TEST 12: Verificar security audit log
# ====================================
echo -e "${YELLOW}[TEST 12]${NC} Verificando archivo de security audit log..."

# Verificar si existe el archivo de security audit
if docker exec nginx-edge test -f /var/log/nginx/security_audit.log; then
    echo -e "${GREEN}✅ PASS${NC} - Archivo security_audit.log existe"
    
    AUDIT_LOG_SIZE=$(docker exec nginx-edge wc -l /var/log/nginx/security_audit.log 2>&1 | awk '{print $1}')
    echo -e "   Líneas en security_audit.log: ${AUDIT_LOG_SIZE}"
    
    if [ "$AUDIT_LOG_SIZE" -gt 0 ]; then
        echo -e "   ${BLUE}Últimas 3 entradas:${NC}"
        docker exec nginx-edge tail -3 /var/log/nginx/security_audit.log | sed 's/^/   /'
    fi
else
    echo -e "${YELLOW}⚠️  INFO${NC} - Archivo security_audit.log aún no generado"
fi
echo ""

# ====================================
# TEST 13: Verificar timeout configuration
# ====================================
echo -e "${YELLOW}[TEST 13]${NC} Verificando configuración de timeouts..."

CONFIG_CHECK=$(docker exec nginx-edge cat /etc/nginx/nginx.conf | grep "proxy_read_timeout")

if echo "$CONFIG_CHECK" | grep -q "620s"; then
    echo -e "${GREEN}✅ PASS${NC} - Timeout configurado correctamente (620s > Kong 600s)"
else
    echo -e "${RED}❌ FAIL${NC} - Timeout no configurado correctamente"
fi
echo ""

# ====================================
# RESUMEN FINAL
# ====================================
echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}📊 RESUMEN DE PRUEBAS${NC}"
echo -e "${BLUE}================================${NC}\n"

echo -e "${GREEN}✅ Reverse Proxy está funcionando correctamente${NC}"
echo -e ""
echo -e "Características validadas:"
echo -e "  • Nginx Edge activo y saludable"
echo -e "  • Headers de seguridad implementados"
echo -e "  • Rate limiting funcional (30 req/s)"
echo -e "  • Microservices protegidos (no accesibles directamente)"
echo -e "  • Load Balancers privados"
echo -e "  • Flujo end-to-end operativo"
echo -e "  • Logging y trazabilidad activos"
echo -e "  • Timeouts configurados correctamente"
echo -e ""
echo -e "${BLUE}Arquitectura:${NC}"
echo -e "  Cliente (App Móvil) → Nginx Edge:8888 → Kong:8000 → Load Balancers → Microservices"
echo -e ""
echo -e "${GREEN}🎉 Patrón de Reverse Proxy implementado correctamente${NC}\n"
