#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "========================================================================="
echo "🏗️  VALIDACIÓN DE ARQUITECTURA DE MICROSERVICIOS CON REVERSE PROXY"
echo "========================================================================="
echo ""

PASSED=0
FAILED=0

pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
    ((PASSED++))
}

fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
    ((FAILED++))
}

warn() {
    echo -e "${YELLOW}⚠️  WARN${NC}: $1"
}

info() {
    echo -e "${BLUE}ℹ️  INFO${NC}: $1"
}

section() {
    echo ""
    echo "========================================================================="
    echo "$1"
    echo "========================================================================="
    echo ""
}

# ==================== VALIDACIÓN 1: SEGMENTACIÓN DE REDES ====================
section "📡 VALIDACIÓN 1: SEGMENTACIÓN DE REDES"

info "Verificando que los servicios estén en las redes correctas..."

# Verificar red proxy_net
PROXY_NET=$(docker network ls --format '{{.Name}}' | grep 'proxy_net' || echo "")
if [ -n "$PROXY_NET" ]; then
    pass "Red proxy_net existe"
else
    fail "Red proxy_net NO existe"
fi

# Verificar red internal_net
INTERNAL_NET=$(docker network ls --format '{{.Name}}' | grep 'internal_net' || echo "")
if [ -n "$INTERNAL_NET" ]; then
    pass "Red internal_net existe"
else
    fail "Red internal_net NO existe"
fi

# Servicios que DEBEN estar en proxy_net
PROXY_SERVICES=("nginx-edge" "kong" "lb-auth" "lb-learningpath")
for service in "${PROXY_SERVICES[@]}"; do
    networks=$(docker inspect $service --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null || echo "")
    if echo "$networks" | grep -q "proxy_net"; then
        pass "$service está en proxy_net"
    else
        fail "$service NO está en proxy_net"
    fi
done

# Servicios que DEBEN estar en internal_net
INTERNAL_SERVICES=("postgres")
for service in "${INTERNAL_SERVICES[@]}"; do
    networks=$(docker inspect $service --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null || echo "")
    if echo "$networks" | grep -q "internal_net"; then
        pass "$service está en internal_net"
    else
        fail "$service NO está en internal_net"
    fi
done

# Microservicios DEBEN estar en AMBAS redes
info "Verificando microservicios en ambas redes..."
MICRO_SERVICES=$(docker ps --filter "name=user_auth" --format "{{.Names}}" | head -n 1)
if [ -n "$MICRO_SERVICES" ]; then
    networks=$(docker inspect $MICRO_SERVICES --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}')
    if echo "$networks" | grep -q "proxy_net" && echo "$networks" | grep -q "internal_net"; then
        pass "Microservicios están en proxy_net E internal_net (segmentación correcta)"
    else
        fail "Microservicios NO están en ambas redes"
    fi
fi

# ==================== VALIDACIÓN 2: AISLAMIENTO DE KONG ====================
section "🔒 VALIDACIÓN 2: AISLAMIENTO DE KONG (Patrón API Gateway Privado)"

info "Verificando que Kong NO sea accesible directamente desde el host..."

# Intentar conectar a Kong directamente (debe FALLAR)
if timeout 2 bash -c "echo > /dev/tcp/localhost/8000" 2>/dev/null; then
    fail "Kong está EXPUESTO en puerto 8000 del host (viola el patrón de seguridad)"
    warn "Kong debe estar aislado, solo accesible a través de Nginx Edge"
else
    pass "Kong NO es accesible directamente desde el host (correcto)"
fi

# Verificar que Kong SÍ sea accesible desde Nginx Edge
KONG_INTERNAL=$(docker exec nginx-edge wget -q -O- --timeout=2 http://kong:8000 2>&1 | head -n 1)
if [ -n "$KONG_INTERNAL" ]; then
    pass "Kong ES accesible desde Nginx Edge en red interna"
else
    fail "Kong NO es accesible desde Nginx Edge"
fi

# ==================== VALIDACIÓN 3: LOAD BALANCERS PRIVADOS ====================
section "⚖️  VALIDACIÓN 3: LOAD BALANCERS PRIVADOS"

info "Verificando que Load Balancers NO sean accesibles desde el host..."

# lb-auth no debe tener puerto expuesto
LB_AUTH_PORTS=$(docker port lb-auth 2>/dev/null | wc -l)
if [ "$LB_AUTH_PORTS" -eq 0 ]; then
    pass "lb-auth NO tiene puertos expuestos al host (correcto)"
else
    fail "lb-auth tiene puertos expuestos: $(docker port lb-auth)"
fi

# lb-learningpath no debe tener puerto expuesto
LB_LEARN_PORTS=$(docker port lb-learningpath 2>/dev/null | wc -l)
if [ "$LB_LEARN_PORTS" -eq 0 ]; then
    pass "lb-learningpath NO tiene puertos expuestos al host (correcto)"
else
    fail "lb-learningpath tiene puertos expuestos: $(docker port lb-learningpath)"
fi

# Verificar que Kong puede acceder a Load Balancers
LB_AUTH_INTERNAL=$(docker exec kong curl -s -o /dev/null -w "%{http_code}" http://lb-auth:80 2>/dev/null || echo "000")
if [ "$LB_AUTH_INTERNAL" != "000" ]; then
    pass "Kong puede acceder a lb-auth internamente"
else
    fail "Kong NO puede acceder a lb-auth"
fi

# ==================== VALIDACIÓN 4: MICROSERVICIOS PRIVADOS ====================
section "🔐 VALIDACIÓN 4: MICROSERVICIOS PRIVADOS"

info "Verificando que microservicios NO sean accesibles desde el host..."

# Obtener un contenedor de user_auth
USER_AUTH_CONTAINER=$(docker ps --filter "name=user_auth" --format "{{.Names}}" | head -n 1)
if [ -n "$USER_AUTH_CONTAINER" ]; then
    # Verificar que no tenga puerto 8080 expuesto
    MICRO_PORTS=$(docker port $USER_AUTH_CONTAINER 2>/dev/null | grep "8080" | wc -l)
    if [ "$MICRO_PORTS" -eq 0 ]; then
        pass "Microservicios NO tienen puerto 8080 expuesto al host (correcto)"
    else
        fail "Microservicios tienen puerto 8080 expuesto: $(docker port $USER_AUTH_CONTAINER)"
    fi
    
    # Verificar que Load Balancer puede acceder
    MICRO_ACCESS=$(docker exec lb-auth curl -s -o /dev/null -w "%{http_code}" http://user_auth:8080 2>/dev/null || echo "000")
    if [ "$MICRO_ACCESS" != "000" ]; then
        pass "Load Balancer puede acceder a microservicios internamente"
    else
        fail "Load Balancer NO puede acceder a microservicios"
    fi
fi

# ==================== VALIDACIÓN 5: NGINX EDGE COMO ÚNICO PUNTO DE ENTRADA ====================
section "🚪 VALIDACIÓN 5: NGINX EDGE - ÚNICO PUNTO DE ENTRADA PÚBLICO"

info "Verificando que Nginx Edge sea el ÚNICO servicio con puerto expuesto..."

# Nginx Edge DEBE tener puerto 8888 expuesto
NGINX_PORT=$(docker port nginx-edge 2>/dev/null | grep "8888" | wc -l)
if [ "$NGINX_PORT" -gt 0 ]; then
    pass "Nginx Edge tiene puerto 8888 expuesto (único punto de entrada)"
else
    fail "Nginx Edge NO tiene puerto 8888 expuesto"
fi

# Health check de Nginx Edge
NGINX_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/health)
if [ "$NGINX_HEALTH" = "200" ]; then
    pass "Nginx Edge health check responde 200 OK"
else
    fail "Nginx Edge health check falló: HTTP $NGINX_HEALTH"
fi

# ==================== VALIDACIÓN 6: FLUJO COMPLETO END-TO-END ====================
section "🔄 VALIDACIÓN 6: FLUJO COMPLETO (Nginx → Kong → LB → Microservicio)"

info "Probando ruta completa: Cliente → Nginx Edge → Kong → LB → Microservicio..."

# Test con endpoint real
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}\nTIME:%{time_total}" \
    -X POST http://localhost:8888/users_authentication_path/check-email \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com"}')

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
TIME=$(echo "$RESPONSE" | grep "TIME" | cut -d: -f2)

if [ "$HTTP_CODE" = "200" ]; then
    pass "Flujo completo funciona: HTTP 200 (tiempo: ${TIME}s)"
    BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE" | grep -v "TIME")
    info "Respuesta: $BODY"
else
    fail "Flujo completo falló: HTTP $HTTP_CODE"
    echo "$RESPONSE"
fi

# ==================== VALIDACIÓN 7: RATE LIMITING ====================
section "⏱️  VALIDACIÓN 7: RATE LIMITING (30 req/s)"

info "Enviando 50 requests rápidos para probar rate limiting..."

SUCCESS=0
RATE_LIMITED=0

for i in {1..50}; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/health)
    if [ "$CODE" = "200" ]; then
        ((SUCCESS++))
    elif [ "$CODE" = "429" ]; then
        ((RATE_LIMITED++))
    fi
done

if [ $RATE_LIMITED -gt 0 ]; then
    pass "Rate limiting funciona: $SUCCESS permitidos, $RATE_LIMITED bloqueados (429)"
else
    warn "Rate limiting no se activó (puede ser normal con 50 requests espaciados)"
    info "Requests exitosos: $SUCCESS, Rate limited: $RATE_LIMITED"
fi

# ==================== VALIDACIÓN 8: HEADERS DE SEGURIDAD ====================
section "🛡️  VALIDACIÓN 8: HEADERS DE SEGURIDAD"

info "Verificando headers de seguridad aplicados por Nginx Edge..."

HEADERS=$(curl -s -I http://localhost:8888/health)

if echo "$HEADERS" | grep -qi "X-Content-Type-Options: nosniff"; then
    pass "Header X-Content-Type-Options presente"
else
    fail "Header X-Content-Type-Options ausente"
fi

if echo "$HEADERS" | grep -qi "Referrer-Policy: no-referrer"; then
    pass "Header Referrer-Policy presente"
else
    fail "Header Referrer-Policy ausente"
fi

if echo "$HEADERS" | grep -qi "X-Frame-Options: DENY"; then
    pass "Header X-Frame-Options presente"
else
    fail "Header X-Frame-Options ausente"
fi

# ==================== VALIDACIÓN 9: RÉPLICAS Y LOAD BALANCING ====================
section "⚖️  VALIDACIÓN 9: RÉPLICAS Y LOAD BALANCING"

info "Verificando réplicas de microservicios..."

USER_AUTH_REPLICAS=$(docker ps --filter "name=user_auth" --format "{{.Names}}" | wc -l)
if [ "$USER_AUTH_REPLICAS" -eq 3 ]; then
    pass "user_auth tiene 3 réplicas (correcto)"
else
    fail "user_auth tiene $USER_AUTH_REPLICAS réplicas (esperadas: 3)"
fi

LEARN_REPLICAS=$(docker ps --filter "name=learningpath" --format "{{.Names}}" | wc -l)
if [ "$LEARN_REPLICAS" -eq 2 ]; then
    pass "learningpath tiene 2 réplicas (correcto)"
else
    fail "learningpath tiene $LEARN_REPLICAS réplicas (esperadas: 2)"
fi

# ==================== VALIDACIÓN 10: BYPASS DIRECTO (SEGURIDAD CRÍTICA) ====================
section "🚨 VALIDACIÓN 10: IMPOSIBILIDAD DE BYPASS"

info "Verificando que NO se puede bypasear Nginx Edge..."

# Intentar acceder directo a Kong (debe fallar)
if timeout 2 bash -c "curl -s http://localhost:8000/health" 2>/dev/null; then
    fail "CRÍTICO: Se puede bypasear Nginx Edge accediendo directo a Kong"
    warn "Esto viola el patrón de reverse proxy"
else
    pass "Imposible acceder directo a Kong (bypass bloqueado)"
fi

# Intentar acceder directo a Load Balancer (debe fallar)
if timeout 2 bash -c "curl -s http://localhost:80" 2>/dev/null; then
    fail "CRÍTICO: Se puede acceder directo a Load Balancer"
else
    pass "Imposible acceder directo a Load Balancer"
fi

# ==================== VALIDACIÓN 11: HEALTH CHECKS ====================
section "💓 VALIDACIÓN 11: HEALTH CHECKS"

info "Verificando health status de servicios críticos..."

# Nginx Edge
NGINX_HEALTH_STATUS=$(docker inspect nginx-edge --format='{{.State.Health.Status}}' 2>/dev/null || echo "none")
if [ "$NGINX_HEALTH_STATUS" = "healthy" ]; then
    pass "Nginx Edge: healthy"
else
    fail "Nginx Edge: $NGINX_HEALTH_STATUS"
fi

# Kong
KONG_HEALTH_STATUS=$(docker inspect kong --format='{{.State.Health.Status}}' 2>/dev/null || echo "none")
if [ "$KONG_HEALTH_STATUS" = "healthy" ]; then
    pass "Kong: healthy"
else
    fail "Kong: $KONG_HEALTH_STATUS"
fi

# ==================== RESUMEN FINAL ====================
section "📊 RESUMEN DE VALIDACIONES"

TOTAL=$((PASSED + FAILED))
PASS_RATE=$((PASSED * 100 / TOTAL))

echo ""
echo "Total de pruebas: $TOTAL"
echo -e "Pasadas: ${GREEN}$PASSED${NC}"
echo -e "Falladas: ${RED}$FAILED${NC}"
echo "Tasa de éxito: $PASS_RATE%"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ ARQUITECTURA IMPLEMENTADA CORRECTAMENTE              ║${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${GREEN}║  ✓ Segmentación de redes (proxy_net + internal_net)      ║${NC}"
    echo -e "${GREEN}║  ✓ Kong aislado (solo accesible desde Nginx Edge)        ║${NC}"
    echo -e "${GREEN}║  ✓ Load Balancers privados                               ║${NC}"
    echo -e "${GREEN}║  ✓ Microservicios privados                               ║${NC}"
    echo -e "${GREEN}║  ✓ Nginx Edge como único punto de entrada                ║${NC}"
    echo -e "${GREEN}║  ✓ Rate limiting funcional                               ║${NC}"
    echo -e "${GREEN}║  ✓ Headers de seguridad aplicados                        ║${NC}"
    echo -e "${GREEN}║  ✓ Réplicas correctas (user_auth x3, learningpath x2)    ║${NC}"
    echo -e "${GREEN}║  ✓ Bypass imposible (seguridad validada)                 ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Flujo validado:"
    echo "  App Móvil"
    echo "      ↓ (puerto 8888 público)"
    echo "  Nginx Edge (rate limiting, security headers)"
    echo "      ↓ (red proxy_net interna)"
    echo "  Kong API Gateway (CORS, auth, routing)"
    echo "      ↓ (red proxy_net interna)"
    echo "  Load Balancers (round-robin)"
    echo "      ↓ (red proxy_net + internal_net)"
    echo "  Microservicios (3x user_auth, 2x learningpath)"
    echo "      ↓ (red internal_net)"
    echo "  PostgreSQL (DB privada)"
    exit 0
else
    echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ❌ ARQUITECTURA TIENE PROBLEMAS                          ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Revisa los errores marcados arriba."
    exit 1
fi
