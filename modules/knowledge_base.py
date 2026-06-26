"""
Base de conhecimento de Event IDs do Windows Server.
Mapeamento de IDs para diagnóstico, severidade e ações recomendadas.
"""

KNOWLEDGE_BASE = {
    # ─── SISTEMA / KERNEL ───────────────────────────────────────────────────
    41: {
        "category": "Sistema",
        "title": "Kernel-Power – Desligamento inesperado",
        "description": "O sistema foi reiniciado sem desligar corretamente. Indica crash, queda de energia ou BSOD.",
        "severity": "Critical",
        "actions": [
            "Verifique o log de Minidump em C:\\Windows\\Minidump",
            "Analise o Event ID 1001 (BugCheck) no mesmo período",
            "Verifique a estabilidade da fonte de alimentação / UPS",
            "Execute 'sfc /scannow' e 'DISM /Online /Cleanup-Image /RestoreHealth'",
            "Verifique drivers de hardware recentemente instalados",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; Id=41} | Select-Object TimeCreated, Message | Format-List",
    },
    1001: {
        "category": "Sistema",
        "title": "BugCheck – Blue Screen of Death (BSOD)",
        "description": "O Windows encontrou um erro crítico e gerou um dump de memória.",
        "severity": "Critical",
        "actions": [
            "Analise o arquivo de dump com WinDbg ou WhoCrashed",
            "Identifique o stop code no campo Message",
            "Verifique drivers com 'verifier /standard /all'",
            "Atualize ou reverta drivers de rede, storage e GPU",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} | Select-Object TimeCreated, Message | Format-List",
    },
    6008: {
        "category": "Sistema",
        "title": "EventLog – Desligamento sujo anterior",
        "description": "O sistema não foi desligado corretamente na sessão anterior.",
        "severity": "Error",
        "actions": [
            "Correlacione com Event ID 41 (Kernel-Power)",
            "Verifique logs de aplicação no mesmo horário",
            "Inspecione hardware (memória RAM com MemTest86)",
            "Revise agendamentos de tarefas e scripts de desligamento",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008} | Select-Object TimeCreated, Message",
    },
    # ─── SEGURANÇA ───────────────────────────────────────────────────────────
    4625: {
        "category": "Segurança",
        "title": "Logon com falha",
        "description": "Tentativa de logon falhou. Pode indicar ataque de força bruta ou credenciais incorretas.",
        "severity": "Warning",
        "actions": [
            "Identifique a conta e o IP de origem no campo Message",
            "Verifique padrão de repetição (possível brute-force)",
            "Implemente bloqueio de conta com Fine-Grained Password Policy",
            "Considere habilitar MFA e revisar políticas de lockout",
            "Bloqueie o IP de origem no firewall se for externo",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Select-Object TimeCreated, Message | Format-List",
    },
    4624: {
        "category": "Segurança",
        "title": "Logon bem-sucedido",
        "description": "Um usuário realizou logon com sucesso no sistema.",
        "severity": "Information",
        "actions": [
            "Monitore logons fora do horário comercial",
            "Verifique logons do tipo 3 (Network) e 10 (RemoteInteractive)",
            "Correlacione com 4625 para identificar tentativas antes do sucesso",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} | Select-Object TimeCreated, Message | Format-List",
    },
    4648: {
        "category": "Segurança",
        "title": "Logon com credenciais explícitas",
        "description": "Um processo tentou fazer logon usando credenciais explícitas (RunAs ou Pass-the-Hash).",
        "severity": "Warning",
        "actions": [
            "Verifique se o uso de RunAs é esperado neste servidor",
            "Investigue possível Pass-the-Hash ou Pass-the-Ticket",
            "Revise contas de serviço com privilégios elevados",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648} | Select-Object TimeCreated, Message | Format-List",
    },
    4720: {
        "category": "Segurança",
        "title": "Conta de usuário criada",
        "description": "Uma nova conta de usuário foi criada no sistema.",
        "severity": "Warning",
        "actions": [
            "Verifique se a criação foi autorizada e documentada",
            "Confirme o criador da conta no campo 'Subject'",
            "Revise se a conta tem privilégios administrativos",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} | Select-Object TimeCreated, Message | Format-List",
    },
    4732: {
        "category": "Segurança",
        "title": "Membro adicionado ao grupo Administrators",
        "description": "Um usuário foi adicionado ao grupo de Administradores locais.",
        "severity": "Critical",
        "actions": [
            "Verifique se a adição foi autorizada pelo time de segurança",
            "Identifique quem realizou a ação no campo 'Subject'",
            "Remova o acesso se não autorizado imediatamente",
            "Revise a política de Least Privilege",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732} | Select-Object TimeCreated, Message | Format-List",
    },
    4740: {
        "category": "Segurança",
        "title": "Conta de usuário bloqueada",
        "description": "Uma conta foi bloqueada após exceder o limite de tentativas de logon.",
        "severity": "Warning",
        "actions": [
            "Identifique a origem dos logons falhos (Event 4625)",
            "Verifique se é bloqueio legítimo ou ataque",
            "Desbloqueie com: Unlock-ADAccount -Identity <usuario>",
            "Revise a política de lockout se bloqueios são frequentes",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} | Select-Object TimeCreated, Message | Format-List",
    },
    # ─── APLICAÇÃO ───────────────────────────────────────────────────────────
    1000: {
        "category": "Aplicação",
        "title": "Application Error – Falha de aplicação",
        "description": "Uma aplicação travou ou gerou erro crítico.",
        "severity": "Error",
        "actions": [
            "Identifique o nome do processo no campo Message",
            "Verifique logs específicos da aplicação",
            "Analise o dump gerado em C:\\Windows\\Temp ou pasta da aplicação",
            "Atualize ou reinstale a aplicação afetada",
            "Verifique dependências (.NET, VC++ Redistributable)",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000} | Select-Object TimeCreated, Message | Format-List",
    },
    1002: {
        "category": "Aplicação",
        "title": "Application Hang – Aplicação travada",
        "description": "Uma aplicação parou de responder.",
        "severity": "Warning",
        "actions": [
            "Verifique uso de CPU e memória no período do evento",
            "Analise deadlocks ou espera por recursos",
            "Considere aumentar timeout da aplicação",
            "Verifique se há atualizações disponíveis",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1002} | Select-Object TimeCreated, Message | Format-List",
    },
    # ─── SERVIÇOS ────────────────────────────────────────────────────────────
    7034: {
        "category": "Sistema",
        "title": "Service Control Manager – Serviço encerrado inesperadamente",
        "description": "Um serviço do Windows encerrou de forma inesperada.",
        "severity": "Error",
        "actions": [
            "Identifique o serviço no campo Message",
            "Verifique logs do serviço específico",
            "Configure recuperação automática: sc failure <servico> reset=86400 actions=restart/5000",
            "Verifique dependências do serviço",
            "Revise permissões da conta de serviço",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7034} | Select-Object TimeCreated, Message | Format-List",
    },
    7031: {
        "category": "Sistema",
        "title": "Service Control Manager – Serviço encerrado e ação de recuperação executada",
        "description": "Um serviço encerrou inesperadamente e a ação de recuperação foi executada.",
        "severity": "Warning",
        "actions": [
            "Verifique quantas vezes o serviço reiniciou",
            "Analise a causa raiz do encerramento",
            "Revise as ações de recuperação configuradas",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7031} | Select-Object TimeCreated, Message | Format-List",
    },
    7036: {
        "category": "Sistema",
        "title": "Service Control Manager – Estado do serviço alterado",
        "description": "Um serviço foi iniciado ou parado.",
        "severity": "Information",
        "actions": [
            "Monitore paradas de serviços críticos fora do horário de manutenção",
            "Correlacione com outros eventos no mesmo período",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} | Select-Object TimeCreated, Message | Format-List",
    },
    # ─── DISCO / STORAGE ─────────────────────────────────────────────────────
    7: {
        "category": "Disco",
        "title": "Disk – Erro de I/O no disco",
        "description": "O driver detectou um erro de controladora no disco.",
        "severity": "Error",
        "actions": [
            "Execute 'chkdsk /f /r' no volume afetado",
            "Verifique o S.M.A.R.T. do disco com CrystalDiskInfo",
            "Revise cabos e conexões SATA/SAS",
            "Planeje substituição do disco se erros forem recorrentes",
            "Verifique logs do controlador RAID",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7} | Select-Object TimeCreated, Message | Format-List",
    },
    51: {
        "category": "Disco",
        "title": "Disk – Erro de paginação no disco",
        "description": "Ocorreu um erro durante operação de paginação no disco.",
        "severity": "Warning",
        "actions": [
            "Verifique a integridade do disco com chkdsk",
            "Analise o arquivo de paginação (pagefile.sys)",
            "Considere mover o pagefile para outro volume",
            "Verifique S.M.A.R.T. do disco",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; Id=51} | Select-Object TimeCreated, Message | Format-List",
    },
    # ─── REDE ────────────────────────────────────────────────────────────────
    4227: {
        "category": "Rede",
        "title": "TCP/IP – Falha de conexão TCP",
        "description": "O sistema falhou ao processar conexões TCP por falta de recursos.",
        "severity": "Warning",
        "actions": [
            "Verifique o número de conexões ativas com 'netstat -an'",
            "Ajuste os parâmetros TCP no registro (TcpTimedWaitDelay)",
            "Verifique se há DDoS ou flood de conexões",
            "Revise limites de conexão da aplicação",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; Id=4227} | Select-Object TimeCreated, Message | Format-List",
    },
    # ─── WINDOWS UPDATE ──────────────────────────────────────────────────────
    19: {
        "category": "Windows Update",
        "title": "Windows Update – Instalação concluída",
        "description": "Uma atualização do Windows foi instalada com sucesso.",
        "severity": "Information",
        "actions": [
            "Documente as atualizações instaladas",
            "Verifique se é necessário reinicialização",
            "Teste funcionalidades críticas após atualização",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; Id=19} | Select-Object TimeCreated, Message",
    },
    20: {
        "category": "Windows Update",
        "title": "Windows Update – Falha na instalação",
        "description": "Uma atualização do Windows falhou ao ser instalada.",
        "severity": "Error",
        "actions": [
            "Anote o código de erro no campo Message",
            "Execute 'sfc /scannow' e tente novamente",
            "Limpe o cache do Windows Update: net stop wuauserv && rd /s /q C:\\Windows\\SoftwareDistribution",
            "Verifique espaço em disco disponível",
            "Consulte o Microsoft Update Catalog para instalação manual",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; Id=20} | Select-Object TimeCreated, Message",
    },
    # ─── ACTIVE DIRECTORY ────────────────────────────────────────────────────
    4776: {
        "category": "Active Directory",
        "title": "NTLM – Validação de credenciais",
        "description": "O DC tentou validar credenciais via NTLM.",
        "severity": "Information",
        "actions": [
            "Monitore falhas de validação NTLM (código de erro diferente de 0x0)",
            "Considere migrar para Kerberos onde possível",
            "Audite uso de NTLM v1 (inseguro)",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4776} | Select-Object TimeCreated, Message | Format-List",
    },
    4771: {
        "category": "Active Directory",
        "title": "Kerberos – Falha na pré-autenticação",
        "description": "A pré-autenticação Kerberos falhou para um usuário.",
        "severity": "Warning",
        "actions": [
            "Verifique se a conta está bloqueada ou expirada",
            "Confirme sincronização de horário entre cliente e DC (máx. 5 min de diferença)",
            "Verifique se há ataque de Kerberoasting",
        ],
        "powershell": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4771} | Select-Object TimeCreated, Message | Format-List",
    },
}

SEVERITY_ORDER = {"Critical": 0, "Error": 1, "Warning": 2, "Information": 3, "Verbose": 4}

SEVERITY_COLORS = {
    "Critical": "#FF4B4B",
    "Error": "#FF8C00",
    "Warning": "#FFD700",
    "Information": "#4CAF50",
    "Verbose": "#9E9E9E",
    "Unknown": "#607D8B",
}

CATEGORY_ICONS = {
    "Segurança": "🔐",
    "Sistema": "⚙️",
    "Aplicação": "📦",
    "Disco": "💾",
    "Rede": "🌐",
    "Windows Update": "🔄",
    "Active Directory": "🏛️",
    "Desconhecido": "❓",
}
