#-
# Copyright (c) 2001, 2003 by Thomas Moestl <tmm@FreeBSD.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# $FreeBSD: src/sys/sparc64/pci/ofw_pci_if.m,v 1.6 2005/01/07 02:29:22 imp Exp $

#include <sys/bus.h>
#include <machine/bus.h>

#include <dev/ofw/openfirm.h>

#include <sparc64/pci/ofw_pci.h>

INTERFACE ofw_pci;

CODE {
	static ofw_pci_intr_pending_t ofw_pci_default_intr_pending;
	static ofw_pci_get_bus_handle_t ofw_pci_default_get_bus_handle;
	static ofw_pci_adjust_busrange_t ofw_pci_default_adjust_busrange;

	static int
	ofw_pci_default_intr_pending(device_t dev, ofw_pci_intr_t intr)
	{

		return (OFW_PCI_INTR_PENDING(device_get_parent(dev), intr));
	}

	static bus_space_handle_t
	ofw_pci_default_get_bus_handle(device_t dev, int type,
	    bus_space_handle_t childhdl, bus_space_tag_t *tag)
	{

		return (OFW_PCI_GET_BUS_HANDLE(device_get_parent(dev), type,
		    childhdl, tag));
	}

	static void
	ofw_pci_default_adjust_busrange(device_t dev, u_int busno)
	{

		return (OFW_PCI_ADJUST_BUSRANGE(device_get_parent(dev), busno));
	}
};

# Return whether an interrupt request is pending for the INO intr.
METHOD int intr_pending {
	device_t dev;
	ofw_pci_intr_t intr;
} DEFAULT ofw_pci_default_intr_pending;

# Get the bustag for the root bus. This is needed for ISA old-stlye
# in[bwl]()/out[bwl]() support, where no tag retrieved from a resource is
# passed. The returned tag is used to construct a tag for the whole ISA bus.
METHOD bus_space_handle_t get_bus_handle {
	device_t dev;
	int type;
	bus_space_handle_t childhdl;
	bus_space_tag_t *tag;
} DEFAULT ofw_pci_default_get_bus_handle;

# Make sure that all PCI bridges up in the hierarchy contain this bus in their
# subordinate bus range. This is required because we reenumerate all PCI
# buses.
METHOD void adjust_busrange {
	device_t dev;
	u_int subbus;
} DEFAULT ofw_pci_default_adjust_busrange;
