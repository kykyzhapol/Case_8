import re

def detect_sql_injections(log):
    sql_patterns = [
        r'\-\-',
        r'((\%27)|(\')).*?(or|and)',
        r"(\b1=1\b)|(\b'a'='a'\b)",
        r'(\b"a"="a"\b)',

        r'((\%27)|(\'))?union',
        r'((\%27)|(\'))?select',
        r'((\%27)|(\'))?insert',
        r'((\%27)|(\'))?update',
        r'((\%27)|(\'))?delete',
        r'((\%27)|(\'))?drop',
        r'((\%27)|(\'))?sleep\(\d+\)',
        r'exec(\s|\+)+(s|x)p\w+'
        ]

    for pattern in sql_patterns:
            if re.search(pattern, log, re.IGNORECASE):
                return True
    return False

def detect_xss_attempts(log):
    xss_patterns = [
        r'<script.*?>.*?</script>',
        r'<iframe.*?>',
        r'javascript:',
        r'<img.*?src.*?=>',
        r'<svg.*?>'
        r'alert\(.*?\)',
        r'eval\(.*?\)',
        ]
    
    for pattern in xss_patterns:
            if re.search(pattern, log, re.IGNORECASE):
                return True
    return False
    

def detect_suspicious_user_agents(log):
    suspicious_agents_patterns = [
        r'bot', r'test', r'debug', r'dev', 
        r'admin', r'root', r'system', r'unknown',
        r'superuser', r'map', r'scanner', r'crawler'
        ]
    
    for pattern in suspicious_agents_patterns:
            if re.search(pattern, log, re.IGNORECASE):
                return True
    return False


def detect_failed_logins(log):
    failed_login_patterns = [
            r'\s([45][0-9][0-9])\s',
            r'status.*?[45][0-9][0-9]'
            ]
    
    for pattern in failed_login_patterns:
            if re.search(pattern, log, re.IGNORECASE):
                return True
    return False


def log_analysis(log_text):
    sql_injections = []
    xss_attempts = []
    suspicious_user_agents = []
    failed_logins = []
    

    for log in log_text:
        if detect_sql_injections(log):
            sql_injections.append(log)

        if detect_xss_attempts(log):
            xss_attempts.append(log)
            
        if detect_suspicious_user_agents(log):
            suspicious_user_agents.append(log)

        if detect_failed_logins(log):
            failed_logins.append(log)
    

    return {
        'sql_injections: ': sql_injections, 
        'xss_attempts: ': xss_attempts, 
        'suspicious_user_agents: ': suspicious_user_agents,
        'failed_logins: ': failed_logins
    }
