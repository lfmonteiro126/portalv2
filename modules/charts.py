"""
Módulo de geração de gráficos com Plotly.
"""

import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from modules.knowledge_base import SEVERITY_COLORS


LEVEL_COLOR_MAP = {
    "Critical": "#FF4B4B",
    "Error": "#FF8C00",
    "Warning": "#FFD700",
    "Information": "#4CAF50",
    "Verbose": "#9E9E9E",
    "Unknown": "#607D8B",
}


def chart_severity_donut(df: pd.DataFrame) -> go.Figure:
    """Gráfico de rosca com distribuição por severidade."""
    counts = df["Level"].value_counts().reset_index()
    counts.columns = ["Level", "Count"]
    colors = [LEVEL_COLOR_MAP.get(lvl, "#607D8B") for lvl in counts["Level"]]

    fig = go.Figure(go.Pie(
        labels=counts["Level"],
        values=counts["Count"],
        hole=0.55,
        marker=dict(colors=colors, line=dict(color="#1E1E2E", width=2)),
        textinfo="label+percent",
        hovertemplate="<b>%{label}</b><br>Eventos: %{value:,}<br>%{percent}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text="Distribuição por Severidade", font=dict(size=16, color="#E0E0E0")),
        paper_bgcolor="#1E1E2E",
        plot_bgcolor="#1E1E2E",
        font=dict(color="#E0E0E0"),
        showlegend=True,
        legend=dict(bgcolor="#2D2D44", bordercolor="#444", borderwidth=1),
        margin=dict(t=50, b=20, l=20, r=20),
        height=350,
    )
    return fig


def chart_timeline(timeline_df: pd.DataFrame) -> go.Figure:
    """Gráfico de linha temporal de eventos por hora."""
    fig = go.Figure()

    level_order = ["Critical", "Error", "Warning", "Information", "Verbose", "Unknown"]
    for level in level_order:
        data = timeline_df[timeline_df["Level"] == level]
        if not data.empty:
            fig.add_trace(go.Scatter(
                x=data["Hour"],
                y=data["Count"],
                name=level,
                mode="lines+markers",
                line=dict(color=LEVEL_COLOR_MAP.get(level, "#607D8B"), width=2),
                marker=dict(size=5),
                hovertemplate=f"<b>{level}</b><br>%{{x}}<br>Eventos: %{{y:,}}<extra></extra>",
            ))

    fig.update_layout(
        title=dict(text="Timeline de Eventos por Hora", font=dict(size=16, color="#E0E0E0")),
        paper_bgcolor="#1E1E2E",
        plot_bgcolor="#1E1E2E",
        font=dict(color="#E0E0E0"),
        xaxis=dict(
            title="Data/Hora",
            gridcolor="#333355",
            showgrid=True,
            color="#E0E0E0",
        ),
        yaxis=dict(
            title="Quantidade de Eventos",
            gridcolor="#333355",
            showgrid=True,
            color="#E0E0E0",
        ),
        legend=dict(bgcolor="#2D2D44", bordercolor="#444", borderwidth=1),
        hovermode="x unified",
        margin=dict(t=50, b=40, l=60, r=20),
        height=380,
    )
    return fig


def chart_top_sources(df: pd.DataFrame, top_n: int = 15) -> go.Figure:
    """Gráfico de barras horizontais com top fontes de eventos."""
    counts = df["Source"].value_counts().head(top_n).reset_index()
    counts.columns = ["Source", "Count"]
    counts = counts.sort_values("Count", ascending=True)

    fig = go.Figure(go.Bar(
        x=counts["Count"],
        y=counts["Source"],
        orientation="h",
        marker=dict(
            color=counts["Count"],
            colorscale=[[0, "#4C6EF5"], [0.5, "#7950F2"], [1, "#FF4B4B"]],
            showscale=False,
        ),
        hovertemplate="<b>%{y}</b><br>Eventos: %{x:,}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text=f"Top {top_n} Fontes de Eventos", font=dict(size=16, color="#E0E0E0")),
        paper_bgcolor="#1E1E2E",
        plot_bgcolor="#1E1E2E",
        font=dict(color="#E0E0E0"),
        xaxis=dict(title="Quantidade", gridcolor="#333355", color="#E0E0E0"),
        yaxis=dict(color="#E0E0E0"),
        margin=dict(t=50, b=40, l=200, r=20),
        height=max(300, top_n * 28),
    )
    return fig


def chart_event_heatmap(df: pd.DataFrame) -> go.Figure:
    """Heatmap de eventos por hora do dia e dia da semana."""
    heatmap_df = df.dropna(subset=["TimeCreated"]).copy()
    heatmap_df["DayOfWeek"] = heatmap_df["TimeCreated"].dt.day_name()
    heatmap_df["HourOfDay"] = heatmap_df["TimeCreated"].dt.hour

    pivot = heatmap_df.groupby(["DayOfWeek", "HourOfDay"]).size().reset_index(name="Count")
    pivot_table = pivot.pivot(index="DayOfWeek", columns="HourOfDay", values="Count").fillna(0)

    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    pivot_table = pivot_table.reindex([d for d in day_order if d in pivot_table.index])

    fig = go.Figure(go.Heatmap(
        z=pivot_table.values,
        x=[f"{h:02d}:00" for h in pivot_table.columns],
        y=pivot_table.index,
        colorscale="Reds",
        hovertemplate="<b>%{y}</b> às %{x}<br>Eventos: %{z:,}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text="Heatmap: Eventos por Hora e Dia da Semana", font=dict(size=16, color="#E0E0E0")),
        paper_bgcolor="#1E1E2E",
        plot_bgcolor="#1E1E2E",
        font=dict(color="#E0E0E0"),
        xaxis=dict(title="Hora do Dia", color="#E0E0E0"),
        yaxis=dict(title="Dia da Semana", color="#E0E0E0"),
        margin=dict(t=50, b=60, l=100, r=20),
        height=320,
    )
    return fig


def chart_top_event_ids(top_df: pd.DataFrame) -> go.Figure:
    """Gráfico de barras com top Event IDs."""
    colors = [LEVEL_COLOR_MAP.get(lvl, "#607D8B") for lvl in top_df["Severity"]]

    fig = go.Figure(go.Bar(
        x=top_df["EventID"].astype(str),
        y=top_df["Count"],
        marker=dict(color=colors, line=dict(color="#1E1E2E", width=1)),
        text=top_df["Count"],
        textposition="outside",
        hovertemplate=(
            "<b>Event ID %{x}</b><br>"
            "Ocorrências: %{y:,}<br>"
            "<extra></extra>"
        ),
    ))
    fig.update_layout(
        title=dict(text="Top Event IDs por Frequência", font=dict(size=16, color="#E0E0E0")),
        paper_bgcolor="#1E1E2E",
        plot_bgcolor="#1E1E2E",
        font=dict(color="#E0E0E0"),
        xaxis=dict(title="Event ID", color="#E0E0E0", type="category"),
        yaxis=dict(title="Ocorrências", gridcolor="#333355", color="#E0E0E0"),
        margin=dict(t=50, b=60, l=60, r=20),
        height=360,
    )
    return fig
