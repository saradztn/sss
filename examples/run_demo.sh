#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== بناء العينة التجريبية =="
make -C samples/demo_app

echo ""
echo "== تحليل ثابت فقط =="
python3 -m revspec.cli analyze samples/demo_app/demo_app --output ./runs

echo ""
echo "== تحليل شامل مع ديناميكي =="
python3 -m revspec.cli analyze samples/demo_app/demo_app --output ./runs --enable-dynamic --dynamic-args="--debug"

echo ""
echo "== التحقق من المخطط =="
latest=$(ls -td ./runs/*/ | head -n 1)
echo "Latest run: $latest"
python3 -m jsonschema -i "$latest/report.json" schemas/report.schema.json && echo "✅ JSON valid"

echo ""
echo "== عرض ملخص =="
cat "$latest/report.json" | python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d['summary'], ensure_ascii=False, indent=2))" "$latest/report.json"
echo ""
echo "✅ تم. التقرير البشري: $latest/report.md"
