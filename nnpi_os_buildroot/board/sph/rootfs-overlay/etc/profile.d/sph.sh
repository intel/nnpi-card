echo "******************************************************"
echo "** Running /etc/profile.d/sph.sh                    **"
echo "******************************************************"

if [ -f /tmp/THIS_IS_A_FULL_OS ]; then
        echo "*****************************************************************"
        echo "** /etc/profile.d/sph.sh: This is a FULL STACK OS              **"
        echo "*****************************************************************"
else
        echo "*****************************************************************"
        echo "** /etc/profile.d/sph.sh: This is an NNPI VANILLA OS           **"
        echo "*****************************************************************"
fi
#Set paths so that logged in user can run tests
set -a
source /usr/local/bin/set-global-sph-paths
set +a

