package main

type GatehouseForm struct {
	TabTitle     string
	FormTitle    string
	FormAction   string
	FormMethod   string
	FormElements []GatehouseFormElement
	OIDCOptions  []OIDCButton
}

type GatehouseFormElement struct {
	Class            string
	InnerText        string
	IsLink           bool
	LinkURI          string
	IsInput          bool
	InputType        string
	InputName        string
	InputPlaceholder string
}

type OIDCButton struct {
	Text            string
	ImageURI        string
	BackgroundColor string
	TextColor       string
	URI             string
}

func FormCreateTextInput(name string, placeholder string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_inp_text",
		"",
		false,
		"",
		true,
		"text",
		name,
		placeholder,
	}
}
func FormCreatePasswordInput(name string, placeholder string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_inp_text",
		"",
		false,
		"",
		true,
		"password",
		name,
		placeholder,
	}
}
func FormCreateSubmitInput(name string, text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_inp_button",
		text,
		false,
		"",
		true,
		"submit",
		name,
		"",
	}
}
func FormCreateButtonLink(linkUrl string, text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_a_button",
		text,
		true,
		linkUrl,
		false,
		"",
		"",
		"",
	}
}
func FormCreateSmallLink(linkUrl string, text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_a_small",
		text,
		true,
		linkUrl,
		false,
		"",
		"",
		"",
	}
}
func FormCreateDivider() GatehouseFormElement {
	return GatehouseFormElement{
		"gh_div_divider",
		"",
		false,
		"",
		false,
		"",
		"",
		"",
	}
}
func FormCreateHint(text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_div_hint",
		text,
		false,
		"",
		false,
		"",
		"",
		"",
	}
}
