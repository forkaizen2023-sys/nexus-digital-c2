# config/regex_rules.py    V.3 validados 
DLP_RULES = {
    # === REGLAS MÁS ESPECÍFICAS PRIMERO (orden crítico) ===
    "JWT_TOKEN": r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}',
    "SSH_PRIVATE": r'-----BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----',
    
    # Tarjeta de crédito con y sin espacios/guiones (captura el caso exacto que estás probando)
    "CREDIT_CARD": r'\b(?:\d[ -]*){13,16}\d\b',
    
    "API_KEY_AWS": r'\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b',
    
    # Genéricas al final
    "SECRET_GENERIC": r'(?i)(?:password|passwd|clave|secret|key|token|api_key|auth|bearer|DB_|ACCESS_)[\s\w_=-]*[\s:=]+["\']?([A-Za-z0-9/_!@#$%^&*()\-+=]{8,128})["\']?',
    "IP_ADDRESS": r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b',
    "EMAIL": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    "DNI_NIE_ES": r'\b(?:[0-9]{8}[A-Z]|[XYZ][0-9]{7}[A-Z])\b',
}
