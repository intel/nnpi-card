echo "******************************************************"
echo "** Running /etc/profile.d/sph.sh                    **"
echo "******************************************************"

if [ -f /tmp/THIS_IS_A_FULL_OS ]; then
        echo "*****************************************************************"
        echo "** /etc/profile.d/sph.sh: This is an FULL STACK OS             **"
        echo "*****************************************************************"
else
        echo "*****************************************************************"
        echo "** /etc/profile.d/sph.sh: This is an SPH VANILLA OS            **"
        echo "*****************************************************************"
fi
#Set paths so that logged in user can run tests
source /usr/local/bin/set-global-sph-paths

