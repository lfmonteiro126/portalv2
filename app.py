"""
Windows Server Event Viewer Portal
Plataforma interativa de análise de logs para administradores Windows Server.
Desenvolvido com Streamlit + Plotly.
"""

import streamlit as st
import pandas as pd
import numpy as np
from pathlib import Path
import base64
import io

# ── Configuração da página ────────────────────────────────────────────────────
st.set_page_config(
    page_title="Windows Log Portal",
    page_icon="🖥️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": None,
        "Report a bug": None,
        "About": "Windows Server Event Viewer Portal v1.0",
    },
)

# ── Módulos internos ──────────────────────────────────────────────────────────
from modules.parser import load_csv
from modules.analyzer import (
    get_summary_stats,
    run_full_analysis,
    get_top_event_ids,
    get_timeline_data,
    get_knowledge_for_event,
)
from modules.charts import (
    chart_severity_donut,
    chart_timeline,
    chart_top_sources,
    chart_event_heatmap,
    chart_top_event_ids,
)
from modules.knowledge_base import (
    KNOWLEDGE_BASE,
    SEVERITY_COLORS,
    CATEGORY_ICONS,
)

# ── CSS ───────────────────────────────────────────────────────────────────────
css_path = Path("assets/style.css")
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)

# ── Estado da sessão ──────────────────────────────────────────────────────────
if "df" not in st.session_state:
    st.session_state.df = None
if "filename" not in st.session_state:
    st.session_state.filename = None


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def severity_badge(level: str) -> str:
    cls = {
        "Critical": "badge-critical",
        "Error": "badge-error",
        "Warning": "badge-warning",
        "Information": "badge-info",
    }.get(level, "badge-info")
    return f'<span class="badge {cls}">{level}</span>'


def severity_icon(level: str) -> str:
    return {
        "Critical": "🔴",
        "Error": "🟠",
        "Warning": "🟡",
        "Information": "🟢",
        "Verbose": "⚪",
    }.get(level, "⚫")


def render_header():
    st.markdown("""
    <div class="main-header">
        <h1>🖥️ Windows Server Event Viewer Portal</h1>
        <p>Análise inteligente de logs · Diagnóstico de incidentes · Troubleshooting assistido</p>
    </div>
    """, unsafe_allow_html=True)


def render_powershell_guide():
    st.markdown("### 📋 Como exportar logs do Event Viewer")

    tab1, tab2, tab3 = st.tabs(["PowerShell (Recomendado)", "Event Viewer GUI", "Dicas de Filtro"])

    with tab1:
        st.markdown("**Exporte os logs diretamente do servidor com PowerShell:**")
        scripts = {
            "System Log (últimos 7 dias)": """Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-7)} |
  Select-Object @{n='EventID';e={$_.Id}},
                @{n='Level';e={$_.LevelDisplayName}},
                @{n='Source';e={$_.ProviderName}},
                TimeCreated,
                @{n='Message';e={$_.Message}},
                @{n='Computer';e={$_.MachineName}},
                @{n='LogName';e={$_.LogName}} |
  Export-Csv -Path "C:\\Logs\\System_$(Get-Date -f yyyyMMdd).csv" -NoTypeInformation -Encoding UTF8""",
            "Security Log (Erros e Críticos)": """Get-WinEvent -FilterHashtable @{LogName='Security'; Level=1,2; StartTime=(Get-Date).AddDays(-7)} |
  Select-Object @{n='EventID';e={$_.Id}},
                @{n='Level';e={$_.LevelDisplayName}},
                @{n='Source';e={$_.ProviderName}},
                TimeCreated,
                @{n='Message';e={$_.Message}},
                @{n='Computer';e={$_.MachineName}} |
  Export-Csv -Path "C:\\Logs\\Security_$(Get-Date -f yyyyMMdd).csv" -NoTypeInformation -Encoding UTF8""",
            "Application Log": """Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddDays(-7)} |
  Select-Object @{n='EventID';e={$_.Id}},
                @{n='Level';e={$_.LevelDisplayName}},
                @{n='Source';e={$_.ProviderName}},
                TimeCreated,
                @{n='Message';e={$_.Message}},
                @{n='Computer';e={$_.MachineName}} |
  Export-Csv -Path "C:\\Logs\\Application_$(Get-Date -f yyyyMMdd).csv" -NoTypeInformation -Encoding UTF8""",
            "Todos os logs críticos (multi-log)": """$logs = @('System','Application','Security')
$all = foreach ($log in $logs) {
    Get-WinEvent -FilterHashtable @{LogName=$log; Level=1,2; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue |
    Select-Object @{n='EventID';e={$_.Id}},
                  @{n='Level';e={$_.LevelDisplayName}},
                  @{n='Source';e={$_.ProviderName}},
                  TimeCreated,
                  @{n='Message';e={$_.Message}},
                  @{n='Computer';e={$_.MachineName}},
                  @{n='LogName';e={$_.LogName}}
}
$all | Export-Csv -Path "C:\\Logs\\CriticalAll_$(Get-Date -f yyyyMMdd).csv" -NoTypeInformation -Encoding UTF8""",
        }
        selected = st.selectbox("Selecione o script:", list(scripts.keys()))
        st.code(scripts[selected], language="powershell")

    with tab2:
        st.markdown("""
        1. Abra o **Event Viewer** (`eventvwr.msc`)
        2. Selecione o log desejado (System, Application, Security)
        3. Clique em **Action → Save All Events As...**
        4. Selecione o formato **CSV (Comma Separated)**
        5. Salve e importe o arquivo aqui
        
        > ⚠️ O formato GUI pode ter colunas diferentes. O script PowerShell é mais confiável.
        """)

    with tab3:
        st.markdown("""
        **Filtros úteis para reduzir o tamanho do arquivo:**
        
        | Cenário | Parâmetro |
        |---------|-----------|
        | Apenas erros e críticos | `Level=1,2` |
        | Últimas 24h | `StartTime=(Get-Date).AddDays(-1)` |
        | Event ID específico | `Id=4625` |
        | Múltiplos IDs | `Id=4625,4624,4740` |
        | Por fonte | `ProviderName='Microsoft-Windows-Security-Auditing'` |
        
        **Limite recomendado:** Exporte no máximo 7 dias por arquivo para melhor performance.
        """)


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────

def render_sidebar():
    with st.sidebar:
        st.markdown("## 🖥️ Windows Log Portal")
        st.markdown("---")

        # ── Upload de arquivo ──────────────────────────────────────────────
        st.markdown("### 📂 Importar Logs")
        uploaded = st.file_uploader(
            "Selecione o arquivo CSV",
            type=["csv"],
            help="Exporte os logs do Event Viewer via PowerShell ou GUI e importe aqui.",
            label_visibility="collapsed",
        )

        if uploaded is not None:
            if (
                st.session_state.filename != uploaded.name
                or st.session_state.df is None
            ):
                with st.spinner("Processando arquivo..."):
                    df, msg = load_csv(uploaded)
                if df is not None:
                    st.session_state.df = df
                    st.session_state.filename = uploaded.name
                    st.success(msg)
                else:
                    st.error(msg)
                    st.session_state.df = None

        # ── Info do arquivo carregado ──────────────────────────────────────
        if st.session_state.df is not None:
            df = st.session_state.df
            st.markdown("---")
            st.markdown("### 📊 Arquivo Carregado")
            st.markdown(f"**Arquivo:** `{st.session_state.filename}`")
            st.markdown(f"**Eventos:** `{len(df):,}`")

            if df["TimeCreated"].notna().any():
                min_d = df["TimeCreated"].min()
                max_d = df["TimeCreated"].max()
                st.markdown(f"**De:** `{min_d.strftime('%d/%m/%Y %H:%M') if pd.notna(min_d) else 'N/A'}`")
                st.markdown(f"**Até:** `{max_d.strftime('%d/%m/%Y %H:%M') if pd.notna(max_d) else 'N/A'}`")

            st.markdown("---")

            # ── Filtros ────────────────────────────────────────────────────
            st.markdown("### 🔍 Filtros")

            levels = ["Todos"] + sorted(df["Level"].unique().tolist())
            selected_level = st.selectbox("Severidade:", levels)

            sources = ["Todas"] + sorted(df["Source"].dropna().unique().tolist())[:50]
            selected_source = st.selectbox("Fonte:", sources)

            event_id_filter = st.text_input(
                "Event ID (ex: 4625 ou 4625,4624):",
                placeholder="Deixe vazio para todos",
            )

            if df["TimeCreated"].notna().any():
                min_date = df["TimeCreated"].min().date()
                max_date = df["TimeCreated"].max().date()
                date_range = st.date_input(
                    "Período:",
                    value=(min_date, max_date),
                    min_value=min_date,
                    max_value=max_date,
                )
            else:
                date_range = None

            st.markdown("---")

            # ── Botão de limpar ────────────────────────────────────────────
            if st.button("🗑️ Limpar Dados", use_container_width=True):
                st.session_state.df = None
                st.session_state.filename = None
                st.rerun()

            return selected_level, selected_source, event_id_filter, date_range

        return None, None, None, None


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINAS
# ─────────────────────────────────────────────────────────────────────────────

def page_dashboard(df: pd.DataFrame):
    """Página principal com visão geral e métricas."""
    stats = get_summary_stats(df)

    # ── Métricas ──────────────────────────────────────────────────────────────
    col1, col2, col3, col4, col5 = st.columns(5)

    metric_data = [
        (col1, "Total de Eventos", f"{stats['total_events']:,}", None),
        (col2, "🔴 Críticos", f"{stats['critical_count']:,}", "red"),
        (col3, "🟠 Erros", f"{stats['error_count']:,}", "orange"),
        (col4, "🟡 Avisos", f"{stats['warning_count']:,}", "yellow"),
        (col5, "🟢 Informativos", f"{stats['info_count']:,}", "green"),
    ]

    for col, label, value, color in metric_data:
        with col:
            st.metric(label=label, value=value)

    st.markdown("---")

    # ── Gráficos principais ───────────────────────────────────────────────────
    col_left, col_right = st.columns([1, 2])

    with col_left:
        st.plotly_chart(chart_severity_donut(df), use_container_width=True)

    with col_right:
        timeline_df = get_timeline_data(df)
        if not timeline_df.empty:
            st.plotly_chart(chart_timeline(timeline_df), use_container_width=True)
        else:
            st.info("Dados de timeline não disponíveis (datas ausentes no CSV).")

    # ── Top Event IDs ─────────────────────────────────────────────────────────
    col_a, col_b = st.columns(2)

    with col_a:
        top_ids = get_top_event_ids(df, top_n=10)
        st.plotly_chart(chart_top_event_ids(top_ids), use_container_width=True)

    with col_b:
        st.plotly_chart(chart_top_sources(df, top_n=12), use_container_width=True)

    # ── Heatmap ───────────────────────────────────────────────────────────────
    if df["TimeCreated"].notna().any():
        st.plotly_chart(chart_event_heatmap(df), use_container_width=True)

    # ── Top Event IDs tabela ──────────────────────────────────────────────────
    st.markdown("### 📋 Top Event IDs Detalhado")
    top_ids_display = top_ids.copy()
    top_ids_display.index = range(1, len(top_ids_display) + 1)
    st.dataframe(
        top_ids_display[["EventID", "Count", "Title", "Category", "Severity"]],
        use_container_width=True,
        column_config={
            "EventID": st.column_config.NumberColumn("Event ID", format="%d"),
            "Count": st.column_config.NumberColumn("Ocorrências", format="%d"),
            "Title": "Descrição",
            "Category": "Categoria",
            "Severity": "Severidade",
        },
    )


def page_incidents(df: pd.DataFrame):
    """Página de detecção de incidentes e alertas."""
    st.markdown("## 🚨 Detecção de Incidentes")
    st.markdown("Análise automática de padrões suspeitos e eventos críticos nos logs importados.")

    with st.spinner("Analisando padrões de incidentes..."):
        incidents = run_full_analysis(df)

    if not incidents:
        st.success("✅ Nenhum incidente detectado nos logs importados.")
        st.info("Os logs não apresentaram padrões de ataques, falhas de serviço ou reinicializações inesperadas.")
        return

    # Resumo
    critical = sum(1 for i in incidents if i["severity"] == "Critical")
    errors = sum(1 for i in incidents if i["severity"] == "Error")
    warnings = sum(1 for i in incidents if i["severity"] == "Warning")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total de Incidentes", len(incidents))
    col2.metric("🔴 Críticos", critical)
    col3.metric("🟠 Erros", errors)
    col4.metric("🟡 Avisos", warnings)

    st.markdown("---")

    # Filtro de severidade
    sev_filter = st.multiselect(
        "Filtrar por severidade:",
        ["Critical", "Error", "Warning", "Information"],
        default=["Critical", "Error", "Warning"],
    )

    filtered_incidents = [i for i in incidents if i["severity"] in sev_filter]

    for incident in filtered_incidents:
        sev = incident["severity"]
        icon = severity_icon(sev)
        css_class = sev.lower() if sev in ("Error", "Warning") else (
            "incident-card" if sev == "Critical" else "info"
        )

        time_str = (
            incident["time"].strftime("%d/%m/%Y %H:%M:%S")
            if pd.notna(incident.get("time")) and incident.get("time") is not None
            else "N/A"
        )

        with st.expander(f"{icon} **{incident['type']}** — {time_str}", expanded=(sev == "Critical")):
            col_info, col_rec = st.columns([1, 1])

            with col_info:
                st.markdown(f"**Severidade:** {severity_badge(sev)}", unsafe_allow_html=True)
                st.markdown(f"**Detectado em:** `{time_str}`")
                st.markdown(f"**Detalhe:** {incident['detail']}")

                if incident.get("event_ids"):
                    ids_str = ", ".join(str(e) for e in incident["event_ids"])
                    st.markdown(f"**Event IDs relacionados:** `{ids_str}`")

            with col_rec:
                st.markdown("**Recomendação:**")
                st.info(incident["recommendation"])

                # Mostra eventos relacionados
                related_ids = incident.get("event_ids", [])
                if related_ids:
                    related_df = df[df["EventID"].isin(related_ids)].head(5)
                    if not related_df.empty:
                        st.markdown("**Eventos relacionados (últimos 5):**")
                        st.dataframe(
                            related_df[["TimeCreated", "EventID", "Level", "Source", "Message"]].head(5),
                            use_container_width=True,
                            hide_index=True,
                        )


def page_explorer(df: pd.DataFrame):
    """Página de exploração e filtragem de logs."""
    st.markdown("## 🔎 Explorador de Logs")

    # Filtros rápidos
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        level_filter = st.multiselect(
            "Severidade:",
            df["Level"].unique().tolist(),
            default=df["Level"].unique().tolist(),
        )
    with col2:
        search_term = st.text_input("Buscar na mensagem:", placeholder="Ex: failed, error, denied...")
    with col3:
        eid_input = st.text_input("Event ID(s):", placeholder="Ex: 4625 ou 4625,4624")
    with col4:
        top_n = st.selectbox("Linhas por página:", [50, 100, 250, 500, 1000], index=1)

    # Aplica filtros
    filtered = df.copy()

    if level_filter:
        filtered = filtered[filtered["Level"].isin(level_filter)]

    if search_term.strip():
        mask = filtered["Message"].astype(str).str.contains(
            search_term.strip(), case=False, na=False
        )
        filtered = filtered[mask]

    if eid_input.strip():
        try:
            eids = [int(x.strip()) for x in eid_input.split(",") if x.strip().isdigit()]
            if eids:
                filtered = filtered[filtered["EventID"].isin(eids)]
        except ValueError:
            st.warning("Event IDs inválidos. Use números separados por vírgula.")

    st.markdown(f"**{len(filtered):,} eventos** encontrados com os filtros aplicados.")

    # Colunas a exibir
    display_cols = ["TimeCreated", "EventID", "Level", "Source", "Computer", "LogName", "Message"]
    display_cols = [c for c in display_cols if c in filtered.columns]

    st.dataframe(
        filtered[display_cols].head(top_n),
        use_container_width=True,
        hide_index=True,
        column_config={
            "TimeCreated": st.column_config.DatetimeColumn("Data/Hora", format="DD/MM/YYYY HH:mm:ss"),
            "EventID": st.column_config.NumberColumn("Event ID", format="%d"),
            "Level": "Severidade",
            "Source": "Fonte",
            "Computer": "Computador",
            "LogName": "Log",
            "Message": st.column_config.TextColumn("Mensagem", width="large"),
        },
    )

    # Export
    st.markdown("---")
    col_exp1, col_exp2 = st.columns([1, 4])
    with col_exp1:
        csv_data = filtered[display_cols].head(top_n).to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            label="⬇️ Exportar Filtrado (CSV)",
            data=csv_data,
            file_name="logs_filtrados.csv",
            mime="text/csv",
            use_container_width=True,
        )


def page_knowledge_base():
    """Página da base de conhecimento de Event IDs."""
    st.markdown("## 📚 Base de Conhecimento — Event IDs")
    st.markdown("Referência completa de Event IDs com diagnóstico e ações recomendadas.")

    # Filtros
    col1, col2, col3 = st.columns(3)
    with col1:
        categories = ["Todas"] + sorted(set(v["category"] for v in KNOWLEDGE_BASE.values()))
        cat_filter = st.selectbox("Categoria:", categories)
    with col2:
        severities = ["Todas", "Critical", "Error", "Warning", "Information"]
        sev_filter = st.selectbox("Severidade:", severities)
    with col3:
        search_kb = st.text_input("Buscar:", placeholder="Ex: logon, disk, service...")

    # Filtra a KB
    kb_items = list(KNOWLEDGE_BASE.items())

    if cat_filter != "Todas":
        kb_items = [(k, v) for k, v in kb_items if v["category"] == cat_filter]
    if sev_filter != "Todas":
        kb_items = [(k, v) for k, v in kb_items if v["severity"] == sev_filter]
    if search_kb.strip():
        term = search_kb.strip().lower()
        kb_items = [
            (k, v) for k, v in kb_items
            if term in v["title"].lower()
            or term in v["description"].lower()
            or term in str(k)
        ]

    st.markdown(f"**{len(kb_items)} Event IDs** na base de conhecimento.")
    st.markdown("---")

    for event_id, info in kb_items:
        cat_icon = CATEGORY_ICONS.get(info["category"], "📌")
        sev_color = SEVERITY_COLORS.get(info["severity"], "#607D8B")

        with st.expander(
            f"{cat_icon} **Event ID {event_id}** — {info['title']}",
            expanded=False,
        ):
            col_main, col_ps = st.columns([3, 2])

            with col_main:
                st.markdown(
                    f"{severity_badge(info['severity'])} "
                    f'<span class="badge" style="background:#2D2D44;color:#8888BB;border:1px solid #444">'
                    f"{cat_icon} {info['category']}</span>",
                    unsafe_allow_html=True,
                )
                st.markdown(f"\n**Descrição:** {info['description']}")

                st.markdown("**Ações Recomendadas:**")
                for i, action in enumerate(info["actions"], 1):
                    st.markdown(f"{i}. {action}")

            with col_ps:
                st.markdown("**Comando PowerShell para consulta:**")
                st.code(info["powershell"], language="powershell")


def page_troubleshoot(df: pd.DataFrame):
    """Assistente de troubleshooting interativo."""
    st.markdown("## 🛠️ Assistente de Troubleshooting")
    st.markdown("Selecione um Event ID para obter diagnóstico detalhado e guia de resolução.")

    col1, col2 = st.columns([1, 2])

    with col1:
        # Event IDs presentes nos logs
        present_ids = sorted(df["EventID"].unique().tolist())
        known_ids = [eid for eid in present_ids if eid in KNOWLEDGE_BASE]
        unknown_ids = [eid for eid in present_ids if eid not in KNOWLEDGE_BASE]

        st.markdown(f"**{len(known_ids)}** Event IDs catalogados nos seus logs")
        st.markdown(f"**{len(unknown_ids)}** Event IDs sem cadastro na KB")

        selected_id = st.selectbox(
            "Selecione o Event ID para diagnóstico:",
            options=known_ids if known_ids else present_ids,
            format_func=lambda x: f"ID {x} — {KNOWLEDGE_BASE.get(x, {}).get('title', 'Sem descrição')[:50]}",
        )

        # Estatísticas do ID selecionado
        id_events = df[df["EventID"] == selected_id]
        st.markdown("---")
        st.markdown(f"**Ocorrências:** `{len(id_events):,}`")

        if id_events["TimeCreated"].notna().any():
            st.markdown(f"**Primeira ocorrência:** `{id_events['TimeCreated'].min().strftime('%d/%m/%Y %H:%M')}`")
            st.markdown(f"**Última ocorrência:** `{id_events['TimeCreated'].max().strftime('%d/%m/%Y %H:%M')}`")

        # Fontes únicas
        unique_sources = id_events["Source"].unique()
        if len(unique_sources) <= 5:
            st.markdown(f"**Fontes:** {', '.join(f'`{s}`' for s in unique_sources)}")

    with col2:
        kb = get_knowledge_for_event(selected_id)

        if kb:
            sev = kb["severity"]
            cat_icon = CATEGORY_ICONS.get(kb["category"], "📌")

            st.markdown(
                f"### {cat_icon} {kb['title']}",
            )
            st.markdown(
                f"{severity_badge(sev)} "
                f'<span class="badge" style="background:#2D2D44;color:#8888BB;border:1px solid #444">'
                f"{kb['category']}</span>",
                unsafe_allow_html=True,
            )

            st.markdown(f"\n**O que significa:** {kb['description']}")

            st.markdown("---")
            st.markdown("#### ✅ Plano de Ação")
            for i, action in enumerate(kb["actions"], 1):
                st.markdown(f"**{i}.** {action}")

            st.markdown("---")
            st.markdown("#### 💻 Comando PowerShell")
            st.code(kb["powershell"], language="powershell")

        else:
            st.warning(f"Event ID **{selected_id}** não está catalogado na base de conhecimento.")
            st.markdown("""
            **Sugestões para investigar:**
            - Consulte o [Microsoft Event Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
            - Pesquise o Event ID no site da Microsoft Learn
            - Verifique a mensagem completa do evento nos logs abaixo
            """)

        # Últimos eventos do ID selecionado
        st.markdown("---")
        st.markdown(f"#### 📋 Últimas ocorrências do Event ID {selected_id}")
        id_events_display = id_events[
            [c for c in ["TimeCreated", "Level", "Source", "Computer", "Message"] if c in id_events.columns]
        ].head(10)

        st.dataframe(
            id_events_display,
            use_container_width=True,
            hide_index=True,
            column_config={
                "TimeCreated": st.column_config.DatetimeColumn("Data/Hora", format="DD/MM/YYYY HH:mm:ss"),
                "Message": st.column_config.TextColumn("Mensagem", width="large"),
            },
        )


def page_welcome():
    """Página de boas-vindas quando nenhum arquivo está carregado."""
    render_powershell_guide()

    st.markdown("---")
    st.markdown("### 🚀 Funcionalidades do Portal")

    col1, col2, col3, col4 = st.columns(4)

    features = [
        (col1, "📊", "Dashboard", "Visão geral com métricas, gráficos de timeline, heatmap e distribuição de severidade."),
        (col2, "🚨", "Detecção de Incidentes", "Análise automática de brute-force, crashes, reinicializações e escalação de privilégios."),
        (col3, "🔎", "Explorador de Logs", "Filtragem avançada por severidade, fonte, Event ID e busca no conteúdo das mensagens."),
        (col4, "🛠️", "Troubleshooting", "Guia de resolução passo-a-passo para cada Event ID com comandos PowerShell prontos."),
    ]

    for col, icon, title, desc in features:
        with col:
            st.markdown(f"""
            <div style="background:#1E1E2E;border:1px solid #2D2D44;border-radius:10px;padding:1.2rem;text-align:center;height:180px">
                <div style="font-size:2rem">{icon}</div>
                <div style="color:#E0E0FF;font-weight:700;margin:0.5rem 0">{title}</div>
                <div style="color:#8888BB;font-size:0.85rem">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 💡 Dica Rápida")
    st.info(
        "Use o painel lateral esquerdo para importar seu arquivo CSV. "
        "Após o carregamento, todas as abas estarão disponíveis com análise completa dos seus logs."
    )


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def apply_filters(df: pd.DataFrame, level, source, event_id_str, date_range) -> pd.DataFrame:
    """Aplica os filtros globais da sidebar ao DataFrame."""
    filtered = df.copy()

    if level and level != "Todos":
        filtered = filtered[filtered["Level"] == level]

    if source and source != "Todas":
        filtered = filtered[filtered["Source"] == source]

    if event_id_str and event_id_str.strip():
        try:
            eids = [int(x.strip()) for x in event_id_str.split(",") if x.strip().isdigit()]
            if eids:
                filtered = filtered[filtered["EventID"].isin(eids)]
        except Exception:
            pass

    if date_range and len(date_range) == 2 and filtered["TimeCreated"].notna().any():
        try:
            start = pd.Timestamp(date_range[0])
            end = pd.Timestamp(date_range[1]) + pd.Timedelta(days=1)
            filtered = filtered[
                (filtered["TimeCreated"] >= start) &
                (filtered["TimeCreated"] < end)
            ]
        except Exception:
            pass

    return filtered


def main():
    render_header()

    # Sidebar retorna os filtros selecionados
    level, source, event_id_str, date_range = render_sidebar()

    if st.session_state.df is None:
        page_welcome()
        return

    # Aplica filtros globais
    df_filtered = apply_filters(
        st.session_state.df, level, source, event_id_str, date_range
    )

    if len(df_filtered) == 0:
        st.warning("Nenhum evento encontrado com os filtros aplicados. Ajuste os filtros na barra lateral.")
        return

    # Navegação por abas
    tab_dash, tab_incidents, tab_explorer, tab_troubleshoot, tab_kb = st.tabs([
        "📊 Dashboard",
        "🚨 Incidentes",
        "🔎 Explorador",
        "🛠️ Troubleshooting",
        "📚 Base de Conhecimento",
    ])

    with tab_dash:
        page_dashboard(df_filtered)

    with tab_incidents:
        page_incidents(df_filtered)

    with tab_explorer:
        page_explorer(df_filtered)

    with tab_troubleshoot:
        if len(df_filtered) > 0:
            page_troubleshoot(df_filtered)

    with tab_kb:
        page_knowledge_base()


if __name__ == "__main__":
    main()
