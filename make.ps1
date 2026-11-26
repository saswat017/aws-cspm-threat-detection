# Windows PowerShell equivalent of the Makefile:  .\make.ps1 <target> [scenario]
param([string]$Target = "help", [string]$Scenario = "all")
$py = "python"
switch ($Target) {
  "install"    { & $py -m pip install -r requirements.txt }
  "lab-up"     { & $py -m lab up }
  "lab-down"   { & $py -m lab down }
  "lab-status" { & $py -m lab status }
  "scan"       { & $py -m scanner scan }
  "diff"       { & $py -m scanner diff }
  "report"     { & $py -m scanner report }
  "detect"     { & $py -m detection run }
  "watch"      { & $py -m detection watch }
  "simulate"   { & $py -m simulation run $Scenario }
  "revert"     { & $py -m simulation revert $Scenario }
  "mttd"       { & $py -m simulation mttd }
  "dashboard"  { & $py -m streamlit run dashboard/app.py }
  "test"       { & $py -m pytest -q }
  default      { Write-Host "Targets: install lab-up lab-down lab-status scan diff report detect watch simulate revert mttd dashboard test" }
}
