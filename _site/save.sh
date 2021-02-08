#!/bin/bash
declare -i versionado=$(cat verss)
echo "adding...."
git add .
echo "probando"
sleep 1
echo "comiteando...."
git commit -m  "v.$versionado"
sleep 1
echo "probando"
((versionado++))
sleep 1
git push
echo $versionado > verss
echo "listo!"
