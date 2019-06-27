git pull origin master
git submodule update

cd ubuntu
sudo apt source openvpn
sudo apt build-dep openvpn
dpkg-source -x openvpn_2.4.4-2ubuntu1.1.dsc
cd openvpn-2.4.4/
dpkg-buildpackage -rfakeroot -b

