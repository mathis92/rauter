/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.routingTable;

import java.util.Arrays;
import java.util.Date;
import java.util.Objects;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.Port;
import sk.mathis.stuba.headers.IpV4Address;

/**
 *
 * @author martinhudec
 */
public class RoutingTableItem {

    byte[] destinationNetwork;
    byte[] netMask;
    String cidrRange;
    byte[] gateway;
    Port port;
    Integer administrativeDistance;
    RouteTypeEnum type;
    Integer metric = 0;
    RipStateEnum ripState;
    Date holdDowntimer = null;
    Date invalidTimer = null;
    Date flushTimer = null;
    Date updateTimer = null;

    public RoutingTableItem(byte[] destinationNetwork, byte[] netMask, byte[] gateway, Port port, Integer administrativeDistance, RouteTypeEnum type) {
        this.destinationNetwork = destinationNetwork;
        this.netMask = netMask;
        this.cidrRange = DataTypeHelper.ipAdressConvertor(destinationNetwork) + "/" + DataTypeHelper.convertNetmaskToCIDR(netMask);
        this.gateway = gateway;
        this.port = port;
        this.administrativeDistance = administrativeDistance;
        this.type = type;

    }

    public RoutingTableItem(byte[] destinationNetwork, byte[] netMask, byte[] gateway, Integer administrativeDistance, Integer metric, RouteTypeEnum type) {
        this.destinationNetwork = destinationNetwork;
        this.netMask = netMask;
        this.cidrRange = new IpV4Address(destinationNetwork) + "/" + DataTypeHelper.convertNetmaskToCIDR(netMask);
        this.gateway = gateway;
        this.port = null;
        this.administrativeDistance = administrativeDistance;
        this.type = type;
        this.metric = metric;
        startTimers();

    }

    public Integer getAdministrativeDistance() {
        return administrativeDistance;
    }

    public byte[] getDestinationNetworkBytes() {
        return destinationNetwork;
    }

    public IpV4Address getDestinationNetwork() {
        return new IpV4Address(destinationNetwork);
    }

    public byte[] getGatewayByte() {
        return gateway;
    }

    public IpV4Address getGateway() {
        return new IpV4Address(gateway);
    }

    public byte[] getNetMask() {
        return netMask;
    }

    public Port getPort() {
        return port;
    }

    public String getCidrRange() {
        return cidrRange;
    }

    public RouteTypeEnum getType() {
        return type;
    }

    public Integer getMetric() {
        return metric;
    }

    public void updateRouteData(byte[] destinationNetwork, byte[] netMask, byte[] gateway, Port port, Integer administrativeDistance, RouteTypeEnum type) {
        this.destinationNetwork = destinationNetwork;
        this.netMask = netMask;
        this.gateway = gateway;
        this.port = port;
        this.cidrRange = DataTypeHelper.ipAdressConvertor(destinationNetwork) + "/" + DataTypeHelper.convertNetmaskToCIDR(netMask);
        this.administrativeDistance = administrativeDistance;
        this.type = type;
    }

    public void updateRouteData(byte[] destinationNetwork, byte[] netMask, byte[] gateway, Integer administrativeDistance, Integer metric, RouteTypeEnum type) {
        if (type == RouteTypeEnum.ripRoute) {
            if (ripState != RipStateEnum.HOLDDOWN) {
                this.destinationNetwork = destinationNetwork;
                this.netMask = netMask;
                this.gateway = gateway;
                this.cidrRange = DataTypeHelper.ipAdressConvertor(destinationNetwork) + "/" + DataTypeHelper.convertNetmaskToCIDR(netMask);
                this.administrativeDistance = administrativeDistance;
                this.type = type;
                this.metric = metric;
                startTimers();
            }
            if (metric == 16) {
                this.destinationNetwork = destinationNetwork;
                this.netMask = netMask;
                this.gateway = gateway;
                this.cidrRange = DataTypeHelper.ipAdressConvertor(destinationNetwork) + "/" + DataTypeHelper.convertNetmaskToCIDR(netMask);
                this.administrativeDistance = administrativeDistance;
                this.type = type;
                this.metric = metric;
            }
        } else {
            this.destinationNetwork = destinationNetwork;
            this.netMask = netMask;
            this.gateway = gateway;
            this.cidrRange = DataTypeHelper.ipAdressConvertor(destinationNetwork) + "/" + DataTypeHelper.convertNetmaskToCIDR(netMask);
            this.administrativeDistance = administrativeDistance;
            this.type = type;
            this.metric = metric;
        }

    }

    public void setState(RipStateEnum state) {
        switch (state) {
            case INVALID: {

                this.ripState = state;
                this.metric = 16;
                break;
            }
            case HOLDDOWN: {

                this.ripState = state;
                break;
            }
            case UPDATE: {

                this.ripState = state;
                break;
            }
            case FLUSH: {

                this.ripState = state;
            }
        }

    }

    public void startTimers() {
        this.ripState = RipStateEnum.UPDATE;
        invalidTimer = new Date();
        holdDowntimer = new Date();
        updateTimer = new Date();
        flushTimer = new Date();
    }

    public Long getInvalidTimer() {
        return new Date().getTime() - invalidTimer.getTime();
    }

    public Long getUpdateTimer() {
        return new Date().getTime() - updateTimer.getTime();
    }

    public Long getHoldDownTimer() {
        return new Date().getTime() - holdDowntimer.getTime();
    }

    public Long getFlushTimer() {
        return new Date().getTime() - flushTimer.getTime();
    }

    public RipStateEnum getRipState() {
        return ripState;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 59 * hash + Arrays.hashCode(this.destinationNetwork);
        hash = 59 * hash + Arrays.hashCode(this.netMask);
        hash = 59 * hash + Arrays.hashCode(this.gateway);
        hash = 59 * hash + Objects.hashCode(this.administrativeDistance);
        hash = 59 * hash + Objects.hashCode(this.type);
        hash = 59 * hash + Objects.hashCode(this.metric);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final RoutingTableItem other = (RoutingTableItem) obj;
        if (!Arrays.equals(this.destinationNetwork, other.destinationNetwork)) {
            return false;
        }
        if (!Arrays.equals(this.netMask, other.netMask)) {
            return false;
        }
        if (!Arrays.equals(this.gateway, other.gateway)) {
            return false;
        }
        if (!Objects.equals(this.administrativeDistance, other.administrativeDistance)) {
            return false;
        }
        if (!Objects.equals(this.type, other.type)) {
            return false;
        }
        if (!Objects.equals(this.metric, other.metric)) {
            return false;
        }
        return true;
    }

}
