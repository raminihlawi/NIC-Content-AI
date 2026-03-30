# NIC-Content-AI

Ett lättviktigt innehålls- och trendflöde för Nordic Information Control.

Repo:t innehåller:

- `trend_radar.py` för trendspaning från Reddit, officiella cyberkällor och regulatoriskt relevanta nyhetskällor
- LinkedIn- och bloggutkast för NIC
- bildprompter anpassade till NIC:s visuella uttryck
- en enkel innehållsmotor i `content/` för återkommande produktion

## Snabbstart

Kör trendradarn:

```bash
python3 trend_radar.py --limit 10
```

Skapa nytt innehåll i Codex / VS Code genom att skriva:

```text
nytt innehåll tack
```

Instruktionerna för det arbetsflödet finns i:

- `content/NIC_CONTENT_PROMPT.md`

## Struktur

- `content/linkedin/` för nya LinkedIn-utkast
- `content/blog/` för nya bloggutkast
- `content/image-prompts/` för bildprompter
- `content/trends/` för trendöversikter och research

## Regional relevans

Trendradarn prioriterar nu inte bara breda cybersäkerhetskällor, utan även europeiska och nordiska/regionala källor som är mer relevanta för NIC:s marknad, till exempel:

- ENISA
- CERT-SE
- NCSC Netherlands
- UK NCSC
- NSM

Det gör det lättare att hitta ämnen som är närmare europeisk reglering, motståndskraft, incidenthantering och styrning.
