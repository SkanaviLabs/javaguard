plugins {
    id("javaguard.java-library")
    id("javaguard.publish")
}

description = "Operating-system TUN interfaces for javaguard (Linux). Uses java.lang.foreign; " +
    "run with --enable-native-access=com.skanavi.javaguard.tun."

dependencies {
    api(project(":javaguard-core"))
}
