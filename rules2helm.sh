# usage: ./rules2helm.sh custom-rules/ingress-traefik.yaml custom-rules/nginx.yaml > custom-rules.yaml
#!/bin/bash

echo "customRules:"
for rules_file in "$@"
do
  echo -e "  $(basename $rules_file): |-"
  while IFS= read -r line || [ -n "$line" ]
  do
    echo -e "    $line"
  done <"$rules_file"
done