# -*- mode: ruby -*-
# vi: set ft=ruby :
# Parcial 2 - Servicios Telematicos - Manuel Betancurt - 2236320
Vagrant.configure("2") do |config|

  # ---------- Servidor 1 : firewall UFW ----------
  config.vm.define :srv1 do |s1|
    s1.vm.box      = "bento/ubuntu-22.04"
    s1.vm.hostname = "srv1-2236320"
    s1.vm.network  :private_network, ip: "192.168.50.3"
    s1.vm.network  :public_network
    s1.vm.provider "virtualbox" do |vb|
      vb.memory = "1024"
      vb.cpus   = 1
    end
  end

  # ---------- Servidor 2 : vsftpd (FTPS) + SFTP ----------
  config.vm.define :srv2 do |s2|
    s2.vm.box      = "bento/ubuntu-22.04"
    s2.vm.hostname = "srv2-2236320"
    s2.vm.network  :private_network, ip: "192.168.50.2"
    s2.vm.provider "virtualbox" do |vb|
      vb.memory = "1024"
      vb.cpus   = 1
    end
  end

  # ---------- Cliente : DoT y pruebas ----------
  config.vm.define :cliente do |c|
    c.vm.box      = "bento/ubuntu-22.04"
    c.vm.hostname = "cli-2236320"
    c.vm.network  :public_network
    c.vm.provider "virtualbox" do |vb|
      vb.memory = "1024"
      vb.cpus   = 1
    end
  end

end