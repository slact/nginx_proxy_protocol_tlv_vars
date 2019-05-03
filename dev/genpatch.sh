#!/usr/bin/zsh
version=$1

ALL_OFF="\e[1;0m"
BOLD="\e[1;1m"
BLUE="${BOLD}\e[1;34m"
YELLOW="${BOLD}\e[1;33m"
RED="${BOLD}\e[1;31m"
GREEN="${BOLD}\e[1;32m"

prompt() {
  echo "${YELLOW}${BOLD}==>${ALL_OFF} $1"
  echo -n "${BLUE}${BOLD}==>${ALL_OFF} "
  read "$2"
}
confirm() {
  prompt "$1 ${YELLOW}[y/N]${ALL_OFF}" _yn
  case $_yn in
    [Yy]* ) return 0;;
    * ) return 1;;
  esac
}

if [[ $1 == "regen" ]]; then
  pushd ..
    current=( `find -maxdepth 1 -type f -name "nginx-*.patch" | sort -r` )
  popd
  for f in $current; do
    ver=$(print $f | sed -r 's/[^-]*-([^-]+).*/\1/')
    echo "${YELLOW}regenerate patch for nginx-${ver}${ALL_OFF}"
    $0 $ver yes quiet
    if ! [ $? -eq 0 ]; then; 
      exit 1
    fi
  done
  exit
fi

base=nginx-$version
patched=nginx-$version-proxy_protocol_vars

mkdir .genpatch 2>/dev/null
rm ".genpatch/$base" -Rf 2>/dev/null
rm ".genpatch/$patched"  -Rf 2>/dev/null
cd .genpatch
if [[ ! -e $base.tar.gz ]]; then
  wget "http://nginx.org/download/$base.tar.gz"
else
  echo "$base.tar.gz already present"
fi
tar xzf $base.tar.gz
cp $base $patched -Rf

pushd ../../src >/dev/null
changed=( `find -type f -not -name "*.orig"` )
popd >/dev/null

for f in $changed; do
  #echo  $f
  diff  -ur ../../src/$f.orig ../../src/$f | patch $patched/src/$f
  if ! [ $? -eq 0 ]; then; 
    failed=1
  fi
done
if [[ -n $failed ]]; then
  echo "${RED}Patch failed, source is too different.${ALL_OFF}"
  exit 1
fi
rm $patched/src/nginx-source 2>/dev/null
rm $patched/src/nginx 2>/dev/null
if [[ $3 != "quiet" ]]; then
  if [[ $2 == "meld" ]]; then
    meld -a  $patched $base
  else
    diff -ur -x '*~' -x '*.swp' $base/src $patched/src | colordiff
  fi
fi
if [[ $2 == "yes" ]] || confirm "Patch for $base looks ok?"; then
  diff -ur -x '*~' -x '*.swp' $base/src $patched/src > ../../$patched.patch
  echo "${GREEN}saved to $patched.patch${ALL_OFF}"
else
  echo "${YELLOW}ok, double-check it then${ALL_OFF}"
fi
rm ".genpatch/$base" ".genpatch/$patched" -Rf

