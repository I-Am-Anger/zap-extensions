version = "0.0.1"
description = "Cross Site Request Forgery Module."

zapAddOn {
    addOnName.set("Cross Site Request Forgery Module")
    zapVersion.set("2.11.1")

    manifest {
        author.set("Aleš Répáš")
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}
