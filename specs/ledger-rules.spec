Name:       ledger-rules
Version:    1
Release:    1
Summary:    Most simple RPM package

%description
This is SPECS file to create rpm package.

%prep
#####

%build
cat > 51-ledger.rules <<EOF
# Ledger: The Original Hardware Wallet
# Put this file into /usr/lib/udev/rules.d

SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", ATTRS{idProduct}=="0000", MODE="0660", TAG+="uaccess", TAG+="udev-acl" OWNER="<UNIX username>"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", ATTRS{idProduct}=="0001", MODE="0660", TAG+="uaccess", TAG+="udev-acl" OWNER="<UNIX username>"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", ATTRS{idProduct}=="0004", MODE="0660", TAG+="uaccess", TAG+="udev-acl" OWNER="<UNIX username>"
EOF

%install
mkdir -p %{buildroot}/lib/udev/rules.d
install -m 644 51-ledger.rules %{buildroot}/lib/udev/rules.d/51-ledger.rules

%files
/lib/udev/rules.d/51-ledger.rules

%changelog
# sudo rpmbuild -ba ledger-rules.spec
# sudo alien ledger-rules-1-1.x86_64.rpm
