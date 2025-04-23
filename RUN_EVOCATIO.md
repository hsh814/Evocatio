# Reproduction of Evocatio results on SymRadar's benchmark

## Prerequisites

The following system packages are required:

- Any POSIX shell
- GNU Core Utilities
- GNU Guix
- GNU Parallel
- GNU Screen
- jq

## Reproduction

Running Evocatio with a 12-hour timeout:

```sh
guix pull
./run-evocatio
```

Run the patch-location-reaching inputs

```sh
for src in */*/default/crashes
do
  dest=../CPR/patches/extractfix/$(dirname $src)/concrete-inputs
  cp -r src dest
  rm dest/README.txt
done

pushd ../CPR/patches/extractfix
./make-uni-klee-select-patch-from-env-var
for script in */*/concrete/run
do
  $script > */*/concrete/result
done
popd
```

Gather statistics:

```sh
echo Remaining patches:
for i in */*/concrete/result
do
  d=$(dirname $(dirname $i))
  echo $d $(python3 filter.py $i $d/concrete-outputs | wc)
done

echo With correct patch ID:
for i in */*/concrete/result
do
  d=$(dirname $(dirname $i))
  echo $d $(python3 filter.py $i $d/concrete-outputs |
    grep -x $(python3 all-patches.py $d t))
done
```
