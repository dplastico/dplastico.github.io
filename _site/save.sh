#!/bin/bash
declare -i versionado=$(cat verss)
echo "adding...."
git add .
echo "Listo!"
sleep 1
echo "comiteando...."
git commit -m  "v.$versionado"
sleep 1
echo "Listo!"
((versionado++))
sleep 1
git push
echo $versionado > verss
echo "listo!, go!"
